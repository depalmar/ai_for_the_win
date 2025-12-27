"""
IOC (Indicator of Compromise) Utilities

Provides safe handling of malicious indicators including:
- Defanging: Make IOCs safe for display/storage (prevent accidental clicks)
- Refanging: Convert back to usable format for analysis tools

Usage:
    from shared.ioc_utils import defang_ioc, refang_ioc, defang_all, is_defanged

    # Defang for safe display
    safe_ip = defang_ioc("185.143.223.47")  # "185[.]143[.]223[.]47"
    safe_url = defang_ioc("http://evil.com")  # "hxxp://evil[.]com"

    # Refang for analysis tools
    real_ip = refang_ioc("185[.]143[.]223[.]47")  # "185.143.223.47"
"""

import re
from typing import Union, List, Dict, Any


def defang_ip(ip: str) -> str:
    """
    Defang an IP address by replacing dots with [.]

    Examples:
        185.143.223.47 -> 185[.]143[.]223[.]47
        192.168.1.1 -> 192[.]168[.]1[.]1 (private IPs also defanged for consistency)
    """
    # IPv4 pattern
    ipv4_pattern = r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})'
    return re.sub(ipv4_pattern, r'\1[.]\2[.]\3[.]\4', ip)


def defang_domain(domain: str) -> str:
    """
    Defang a domain by replacing the last dot with [.]

    Examples:
        evil-c2.com -> evil-c2[.]com
        malware.drop.net -> malware.drop[.]net
    """
    # Find the last dot before the TLD and replace it
    if '.' in domain:
        parts = domain.rsplit('.', 1)
        return f"{parts[0]}[.]{parts[1]}"
    return domain


def defang_url(url: str) -> str:
    """
    Defang a URL by replacing http(s):// with hxxp(s):// and dots in domain

    Examples:
        http://evil.com/path -> hxxp://evil[.]com/path
        https://malware.net -> hxxps://malware[.]net
    """
    # Replace protocol
    url = re.sub(r'^http://', 'hxxp://', url, flags=re.IGNORECASE)
    url = re.sub(r'^https://', 'hxxps://', url, flags=re.IGNORECASE)

    # Extract and defang domain
    match = re.match(r'(hxxps?://)([^/]+)(.*)', url, re.IGNORECASE)
    if match:
        protocol, domain, path = match.groups()
        # Defang the domain part
        defanged_domain = defang_domain(domain)
        return f"{protocol}{defanged_domain}{path}"

    return url


def defang_email(email: str) -> str:
    """
    Defang an email address by replacing @ with [@] and dot in domain

    Examples:
        attacker@evil.com -> attacker[@]evil[.]com
    """
    if '@' in email:
        local, domain = email.rsplit('@', 1)
        return f"{local}[@]{defang_domain(domain)}"
    return email


def defang_ioc(ioc: str, ioc_type: str = "auto") -> str:
    """
    Defang an IOC based on its type.

    Args:
        ioc: The indicator to defang
        ioc_type: One of "ip", "domain", "url", "email", or "auto" (auto-detect)

    Returns:
        Defanged IOC string
    """
    if ioc_type == "auto":
        # Auto-detect IOC type
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            ioc_type = "ip"
        elif re.match(r'^https?://', ioc, re.IGNORECASE):
            ioc_type = "url"
        elif '@' in ioc:
            ioc_type = "email"
        else:
            ioc_type = "domain"

    if ioc_type == "ip":
        return defang_ip(ioc)
    elif ioc_type == "url":
        return defang_url(ioc)
    elif ioc_type == "email":
        return defang_email(ioc)
    elif ioc_type == "domain":
        return defang_domain(ioc)
    else:
        return ioc


def refang_ioc(ioc: str) -> str:
    """
    Convert a defanged IOC back to its original form.

    WARNING: Use with caution - refanged IOCs may be dangerous!
    Only refang when feeding to analysis tools, not for display.

    Examples:
        185[.]143[.]223[.]47 -> 185.143.223.47
        hxxp://evil[.]com -> http://evil.com
        attacker[@]evil[.]com -> attacker@evil.com
    """
    # Replace defanged dots
    result = ioc.replace('[.]', '.').replace('[dot]', '.')

    # Replace defanged protocols
    result = re.sub(r'^hxxp://', 'http://', result, flags=re.IGNORECASE)
    result = re.sub(r'^hxxps://', 'https://', result, flags=re.IGNORECASE)

    # Replace defanged email @
    result = result.replace('[@]', '@').replace('[at]', '@')

    return result


def is_defanged(ioc: str) -> bool:
    """Check if an IOC is already defanged."""
    defang_patterns = [
        r'\[\.\]',      # [.]
        r'\[dot\]',     # [dot]
        r'hxxps?://',   # hxxp:// or hxxps://
        r'\[@\]',       # [@]
        r'\[at\]',      # [at]
    ]
    return any(re.search(pattern, ioc, re.IGNORECASE) for pattern in defang_patterns)


def defang_all(text: str) -> str:
    """
    Defang all IOCs found in a text string.

    Handles:
    - IPv4 addresses
    - URLs
    - Email addresses
    - Domains (limited - only obvious patterns)
    """
    # Defang IPs
    text = re.sub(
        r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b',
        r'\1[.]\2[.]\3[.]\4',
        text
    )

    # Defang URLs
    text = re.sub(r'http://', 'hxxp://', text, flags=re.IGNORECASE)
    text = re.sub(r'https://', 'hxxps://', text, flags=re.IGNORECASE)

    # Defang emails
    text = re.sub(r'(\S+)@(\S+)', r'\1[@]\2', text)

    return text


def defang_dict(data: Dict[str, Any], keys_to_defang: List[str] = None) -> Dict[str, Any]:
    """
    Recursively defang IOCs in a dictionary.

    Args:
        data: Dictionary potentially containing IOCs
        keys_to_defang: List of key names that contain IOCs to defang.
                       If None, uses default IOC-related keys.

    Returns:
        Dictionary with defanged IOCs
    """
    if keys_to_defang is None:
        keys_to_defang = [
            'ip', 'ips', 'ip_address', 'src_ip', 'dst_ip', 'source_ip', 'destination_ip',
            'domain', 'domains', 'hostname', 'host',
            'url', 'urls', 'uri', 'link',
            'email', 'emails', 'from', 'to', 'reply_to',
            'c2', 'c2_server', 'callback',
            'related_domains', 'related_ips'
        ]

    def _defang_value(value: Any, key: str = None) -> Any:
        if isinstance(value, str):
            # Only defang if it looks like an IOC
            if key and key.lower() in keys_to_defang:
                return defang_ioc(value)
            return value
        elif isinstance(value, list):
            return [_defang_value(item, key) for item in value]
        elif isinstance(value, dict):
            return {k: _defang_value(v, k) for k, v in value.items()}
        return value

    return _defang_value(data)


# Safe private IP ranges (RFC1918) - these don't need to be treated as dangerous
PRIVATE_IP_RANGES = [
    (r'^10\.', 'Class A private'),
    (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 'Class B private'),
    (r'^192\.168\.', 'Class C private'),
    (r'^127\.', 'Loopback'),
    (r'^0\.', 'Current network'),
]


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    for pattern, _ in PRIVATE_IP_RANGES:
        if re.match(pattern, ip):
            return True
    return False


def classify_ip_risk(ip: str) -> str:
    """
    Classify IP risk level.

    Returns:
        "safe" - Private/reserved IP
        "unknown" - Public IP, unknown reputation
        "check" - Should be checked against threat intel
    """
    if is_private_ip(ip):
        return "safe"

    # Well-known safe IPs (extend as needed)
    safe_ips = [
        '8.8.8.8', '8.8.4.4',  # Google DNS
        '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
    ]
    if ip in safe_ips:
        return "safe"

    return "check"


if __name__ == "__main__":
    # Demo/test
    print("=== IOC Defanging Demo ===\n")

    test_cases = [
        ("185.143.223.47", "ip"),
        ("evil-c2.com", "domain"),
        ("http://malware.net/payload.exe", "url"),
        ("attacker@evil.com", "email"),
    ]

    for ioc, ioc_type in test_cases:
        defanged = defang_ioc(ioc, ioc_type)
        refanged = refang_ioc(defanged)
        print(f"{ioc_type.upper():10} Original: {ioc}")
        print(f"           Defanged: {defanged}")
        print(f"           Refanged: {refanged}")
        print(f"           Match: {'✓' if refanged == ioc else '✗'}\n")

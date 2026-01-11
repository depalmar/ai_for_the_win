# IOC (Indicator of Compromise) Patterns

Regex patterns and validation rules for extracting and defanging IOCs.

## IP Addresses

### IPv4
```regex
# Basic IPv4
\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b

# IPv4 with port
\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\d{1,5}\b

# Defanged IPv4 (common patterns)
\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[?\.\]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
```

Python:
```python
import re

IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Defanged patterns
IPV4_DEFANGED = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[?\.\]?){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
```

### IPv6
```regex
# Full IPv6
\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b

# Compressed IPv6 (simplified)
\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b

# IPv6 with zone ID
\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}%\w+\b
```

### Private/Reserved IP Ranges
| Range | CIDR | Description |
|-------|------|-------------|
| 10.0.0.0 - 10.255.255.255 | 10.0.0.0/8 | Private Class A |
| 172.16.0.0 - 172.31.255.255 | 172.16.0.0/12 | Private Class B |
| 192.168.0.0 - 192.168.255.255 | 192.168.0.0/16 | Private Class C |
| 127.0.0.0 - 127.255.255.255 | 127.0.0.0/8 | Loopback |
| 169.254.0.0 - 169.254.255.255 | 169.254.0.0/16 | Link-local |
| 0.0.0.0 | 0.0.0.0/32 | Default route |

```python
import ipaddress

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return False
```

## Domains

### Basic Domain
```regex
# Domain (excluding IP addresses)
\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b

# Domain with optional port
\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d{1,5})?\b

# Subdomain extraction
(?:([a-zA-Z0-9\-]+)\.)*([a-zA-Z0-9\-]+)\.([a-zA-Z]{2,})
```

### Defanged Domains
```regex
# Common defanging patterns
\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\[?\.\]?)+[a-zA-Z]{2,}\b

# hxxp style
hxxps?://[^\s]+

# [dot] style
\b\S+\[dot\]\S+\b
```

Python:
```python
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

def refang_domain(domain: str) -> str:
    """Convert defanged domain to normal."""
    return (domain
        .replace('[.]', '.')
        .replace('[dot]', '.')
        .replace('(.)', '.')
        .replace('{.}', '.'))
```

### TLD Validation
```python
# Common TLDs for filtering
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'icu', 'buzz',
    'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs often abused
    'ru', 'cn', 'su',  # Country codes often seen in attacks
}
```

## URLs

### Full URL
```regex
# HTTP/HTTPS URLs
https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*

# More permissive (with auth, port, path)
https?://(?:[\w\-]+(?::[\w\-]+)?@)?(?:[\w\-]+\.)+[\w\-]+(?::\d+)?(?:/[^\s]*)?
```

### Defanged URLs
```regex
# hxxp patterns
hxxps?://[^\s]+

# Multiple defanging styles
(?:hxxps?|https?)\[?:\]?//[^\s]+
```

Python:
```python
URL_PATTERN = re.compile(
    r'https?://(?:[\w\-]+\.)+[\w\-]+(?::\d+)?(?:/[^\s]*)?',
    re.IGNORECASE
)

def refang_url(url: str) -> str:
    """Convert defanged URL to normal."""
    return (url
        .replace('hxxp', 'http')
        .replace('hXXp', 'http')
        .replace('[:]', ':')
        .replace('[.]', '.')
        .replace('[/]', '/')
        .replace('(.)', '.')
        .replace('[dot]', '.'))

def defang_url(url: str) -> str:
    """Defang a URL for safe sharing."""
    return (url
        .replace('http', 'hxxp')
        .replace('://', '[://]')
        .replace('.', '[.]'))
```

## File Hashes

### MD5
```regex
\b[a-fA-F0-9]{32}\b
```

### SHA1
```regex
\b[a-fA-F0-9]{40}\b
```

### SHA256
```regex
\b[a-fA-F0-9]{64}\b
```

### SHA512
```regex
\b[a-fA-F0-9]{128}\b
```

### All Hashes (Combined)
```python
HASH_PATTERNS = {
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'sha512': re.compile(r'\b[a-fA-F0-9]{128}\b'),
}

def identify_hash_type(hash_value: str) -> str:
    """Identify hash type by length."""
    hash_value = hash_value.strip().lower()
    if not re.match(r'^[a-f0-9]+$', hash_value):
        return 'invalid'

    lengths = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}
    return lengths.get(len(hash_value), 'unknown')
```

## Email Addresses

### Basic Email
```regex
\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
```

### Defanged Email
```regex
\b[A-Za-z0-9._%+-]+\[?@\]?[A-Za-z0-9.-]+\[?\.\]?[A-Z|a-z]{2,}\b
```

Python:
```python
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    re.IGNORECASE
)

def defang_email(email: str) -> str:
    """Defang an email address."""
    return email.replace('@', '[@]').replace('.', '[.]')

def refang_email(email: str) -> str:
    """Refang a defanged email."""
    return email.replace('[@]', '@').replace('[.]', '.').replace('[at]', '@')
```

## CVE Identifiers

```regex
# CVE pattern
CVE-\d{4}-\d{4,}

# Case insensitive
(?i)CVE-\d{4}-\d{4,}
```

Python:
```python
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
```

## MITRE ATT&CK IDs

```regex
# Technique IDs
T\d{4}(?:\.\d{3})?

# Tactic IDs
TA\d{4}

# Group IDs
G\d{4}

# Software IDs
S\d{4}

# Mitigation IDs
M\d{4}
```

Python:
```python
MITRE_PATTERNS = {
    'technique': re.compile(r'T\d{4}(?:\.\d{3})?'),
    'tactic': re.compile(r'TA\d{4}'),
    'group': re.compile(r'G\d{4}'),
    'software': re.compile(r'S\d{4}'),
    'mitigation': re.compile(r'M\d{4}'),
}
```

## Registry Keys

```regex
# Windows registry paths
(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)\\[^\s]+

# Common malware persistence keys
(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|Services\\|Winlogon\\)
```

## File Paths

### Windows Paths
```regex
# Full Windows path
[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*

# UNC path
\\\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+(?:\\[^\\/:*?"<>|\r\n]+)*
```

### Unix Paths
```regex
# Unix absolute path
/(?:[^/\0]+/)*[^/\0]*
```

### Suspicious Paths
```python
SUSPICIOUS_PATHS = [
    r'\\Temp\\',
    r'\\AppData\\Local\\Temp\\',
    r'\\Users\\Public\\',
    r'\\ProgramData\\',
    r'\\Windows\\Temp\\',
    r'/tmp/',
    r'/var/tmp/',
    r'/dev/shm/',
]
```

## YARA Rule Patterns

### String Patterns in YARA
```yara
rule Example {
    strings:
        // Hex string
        $hex = { 4D 5A 90 00 }

        // Text string
        $text = "malware" nocase

        // Regex
        $regex = /https?:\/\/[^\s]+/

        // Wide string (UTF-16)
        $wide = "password" wide

        // XOR encoded
        $xor = "secret" xor

    condition:
        any of them
}
```

## Complete IOC Extractor

```python
import re
from dataclasses import dataclass
from typing import List, Set

@dataclass
class IOCResults:
    ipv4: Set[str]
    ipv6: Set[str]
    domains: Set[str]
    urls: Set[str]
    emails: Set[str]
    md5: Set[str]
    sha1: Set[str]
    sha256: Set[str]
    cves: Set[str]

class IOCExtractor:
    PATTERNS = {
        'ipv4': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'domain': re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        'url': re.compile(
            r'https?://(?:[\w\-]+\.)+[\w\-]+(?::\d+)?(?:/[^\s]*)?',
            re.IGNORECASE
        ),
        'email': re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            re.IGNORECASE
        ),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'cve': re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
    }

    @classmethod
    def extract(cls, text: str) -> IOCResults:
        """Extract all IOCs from text."""
        # Refang first
        text = cls.refang(text)

        return IOCResults(
            ipv4=set(cls.PATTERNS['ipv4'].findall(text)),
            ipv6=set(),  # Add IPv6 pattern as needed
            domains=set(cls.PATTERNS['domain'].findall(text)),
            urls=set(cls.PATTERNS['url'].findall(text)),
            emails=set(cls.PATTERNS['email'].findall(text)),
            md5=set(cls.PATTERNS['md5'].findall(text)),
            sha1=set(cls.PATTERNS['sha1'].findall(text)),
            sha256=set(cls.PATTERNS['sha256'].findall(text)),
            cves=set(cls.PATTERNS['cve'].findall(text)),
        )

    @staticmethod
    def refang(text: str) -> str:
        """Refang defanged IOCs."""
        replacements = [
            ('hxxp', 'http'),
            ('hXXp', 'http'),
            ('[.]', '.'),
            ('(.)', '.'),
            ('[dot]', '.'),
            ('[:]', ':'),
            ('[@]', '@'),
            ('[at]', '@'),
        ]
        for old, new in replacements:
            text = text.replace(old, new)
        return text

    @staticmethod
    def defang(text: str, ioc_type: str = 'all') -> str:
        """Defang IOCs for safe sharing."""
        if ioc_type in ('url', 'all'):
            text = text.replace('http', 'hxxp')
        if ioc_type in ('ip', 'domain', 'url', 'all'):
            # Defang dots (but not in hashes)
            text = re.sub(r'\.(?=\d|[a-zA-Z])', '[.]', text)
        if ioc_type in ('email', 'all'):
            text = text.replace('@', '[@]')
        return text
```

## Validation Tips

1. **Filter false positives**: Version numbers (1.2.3.4), timestamps, UUIDs
2. **Check context**: Is the IP in a log timestamp or actual network traffic?
3. **Validate TLDs**: Filter out invalid/uncommon TLDs
4. **Check private ranges**: Exclude RFC1918 addresses if looking for external threats
5. **Deduplicate**: Same IOC may appear multiple times
6. **Normalize**: Lowercase domains, uppercase hashes for consistency

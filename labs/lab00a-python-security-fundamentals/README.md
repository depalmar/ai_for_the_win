# Lab 00a: Python for Security Fundamentals

**Difficulty: ⭐️ Easy | Time: 3-4 hours | No Prerequisites**

Welcome to AI for the Win! This introductory lab teaches Python basics through security-focused examples. No prior programming experience required.

## Learning Objectives

By the end of this lab, you will:
1. Write and run Python scripts
2. Work with strings, lists, and dictionaries
3. Read and write files (logs, CSVs)
4. Make HTTP requests to APIs
5. Parse and analyze security data

## Estimated Time

3-4 hours (take your time! This covers everything you need for Labs 01-10)

## Prerequisites

- Python 3.9+ installed ([Download Python](https://www.python.org/downloads/))
- A code editor (VS Code, Cursor, or any text editor)
- Curiosity and patience

---

## Part 1: Python Basics

### 1.1 Your First Python Script

Create a file called `hello_security.py`:

```python
# This is a comment - Python ignores lines starting with #
print("Welcome to AI for the Win!")
print("Let's learn Python for security!")
```

Run it:
```bash
python hello_security.py
```

### 1.2 Variables and Data Types

Variables store data. Python figures out the type automatically.

```python
# Strings - text data (use quotes)
ip_address = "192.168.1.100"
hostname = "workstation-01"
alert_message = "Suspicious login detected"

# Numbers
port = 443
failed_attempts = 5
risk_score = 7.5

# Booleans - True or False
is_malicious = True
is_whitelisted = False

# Print variables
print(f"Alert: {alert_message}")
print(f"Source IP: {ip_address}:{port}")
print(f"Failed attempts: {failed_attempts}")
```

**Try it:** Create variables for a security event (timestamp, user, action).

### 1.3 Lists - Collections of Items

Lists hold multiple items in order.

```python
# List of suspicious IPs
suspicious_ips = ["10.0.0.5", "192.168.1.100", "172.16.0.50"]

# Access items by index (starts at 0)
first_ip = suspicious_ips[0]  # "10.0.0.5"
last_ip = suspicious_ips[-1]  # "172.16.0.50"

# Add items
suspicious_ips.append("10.10.10.10")

# Check if item exists
if "192.168.1.100" in suspicious_ips:
    print("IP is in the suspicious list!")

# Loop through items
print("Blocking these IPs:")
for ip in suspicious_ips:
    print(f"  - {ip}")

# Get count
print(f"Total suspicious IPs: {len(suspicious_ips)}")
```

### 1.4 Dictionaries - Key-Value Pairs

Dictionaries map keys to values (like a lookup table).

```python
# Security event as a dictionary
event = {
    "timestamp": "2024-01-15T10:30:00Z",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.5",
    "port": 443,
    "action": "blocked",
    "severity": "high"
}

# Access values by key
print(f"Event severity: {event['severity']}")
print(f"Source: {event['source_ip']}")

# Add new key
event["analyst"] = "alice"

# Check if key exists
if "severity" in event:
    print("Severity is defined")

# Loop through keys and values
for key, value in event.items():
    print(f"  {key}: {value}")
```

### 1.5 Conditionals - Making Decisions

```python
severity = "critical"
failed_logins = 10

# if-elif-else
if severity == "critical":
    print("ALERT: Immediate response required!")
elif severity == "high":
    print("Warning: Review within 1 hour")
elif severity == "medium":
    print("Notice: Review within 24 hours")
else:
    print("Info: Log for reference")

# Multiple conditions
if failed_logins > 5 and severity in ["high", "critical"]:
    print("Account lockout recommended")

# Ternary (one-liner)
status = "blocked" if failed_logins > 3 else "allowed"
```

### 1.6 Loops - Repeating Actions

```python
# For loop - iterate over a sequence
ports = [22, 80, 443, 8080]
for port in ports:
    print(f"Scanning port {port}...")

# For loop with range
print("Counting failed attempts:")
for i in range(1, 6):
    print(f"  Attempt {i}")

# While loop - repeat until condition is false
attempts = 0
max_attempts = 3
while attempts < max_attempts:
    print(f"Login attempt {attempts + 1}")
    attempts += 1
print("Max attempts reached - account locked")

# Loop with enumerate (get index and value)
alerts = ["Malware detected", "Port scan", "Brute force"]
for index, alert in enumerate(alerts):
    print(f"Alert #{index + 1}: {alert}")
```

### 1.7 Functions - Reusable Code

```python
def calculate_risk_score(failed_logins, is_admin, is_after_hours):
    """
    Calculate risk score based on login behavior.

    Args:
        failed_logins: Number of failed login attempts
        is_admin: Whether the account is an admin
        is_after_hours: Whether the attempt is outside business hours

    Returns:
        Risk score from 0-10
    """
    score = 0

    # Base score from failed logins
    score += min(failed_logins, 5)  # Cap at 5 points

    # Admin accounts are higher risk
    if is_admin:
        score += 3

    # After-hours activity is suspicious
    if is_after_hours:
        score += 2

    return min(score, 10)  # Cap at 10

# Use the function
risk = calculate_risk_score(failed_logins=4, is_admin=True, is_after_hours=True)
print(f"Risk score: {risk}/10")

if risk >= 7:
    print("HIGH RISK - Investigate immediately")
```

---

## Part 2: Working with Files

### 2.1 Reading Text Files

```python
# Read entire file
with open("access.log", "r") as file:
    content = file.read()
    print(content)

# Read line by line (memory efficient for large files)
with open("access.log", "r") as file:
    for line in file:
        line = line.strip()  # Remove whitespace
        if "ERROR" in line:
            print(f"Found error: {line}")
```

### 2.2 Writing Files

```python
# Write to a file (overwrites existing)
with open("blocked_ips.txt", "w") as file:
    file.write("192.168.1.100\n")
    file.write("10.0.0.5\n")

# Append to a file
with open("blocked_ips.txt", "a") as file:
    file.write("172.16.0.50\n")

# Write multiple lines
blocked_ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
with open("blocked_ips.txt", "w") as file:
    for ip in blocked_ips:
        file.write(f"{ip}\n")
```

### 2.3 Working with CSV Files

```python
import csv

# Read CSV file
with open("alerts.csv", "r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        print(f"Alert: {row['description']} - Severity: {row['severity']}")

# Write CSV file
alerts = [
    {"timestamp": "2024-01-15", "type": "malware", "severity": "high"},
    {"timestamp": "2024-01-15", "type": "phishing", "severity": "medium"},
]

with open("output.csv", "w", newline="") as file:
    fieldnames = ["timestamp", "type", "severity"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(alerts)
```

### 2.4 Working with JSON

```python
import json

# Read JSON file
with open("config.json", "r") as file:
    config = json.load(file)
    print(f"API endpoint: {config['api_url']}")

# Write JSON file
event = {
    "id": "EVT-001",
    "type": "login_failure",
    "details": {
        "user": "admin",
        "ip": "192.168.1.100",
        "attempts": 5
    }
}

with open("event.json", "w") as file:
    json.dump(event, file, indent=2)

# Parse JSON string
json_string = '{"ip": "10.0.0.1", "port": 443}'
data = json.loads(json_string)
print(f"IP: {data['ip']}")
```

---

## Part 3: Security Examples

### 3.1 Log Parser

```python
def parse_log_line(line):
    """Parse a simple log line into components."""
    parts = line.strip().split(" ")
    if len(parts) >= 4:
        return {
            "timestamp": parts[0],
            "level": parts[1],
            "source": parts[2],
            "message": " ".join(parts[3:])
        }
    return None

# Sample log data
log_lines = [
    "2024-01-15T10:00:00 INFO auth Login successful for user alice",
    "2024-01-15T10:05:00 ERROR auth Failed login for user bob from 192.168.1.100",
    "2024-01-15T10:06:00 ERROR auth Failed login for user bob from 192.168.1.100",
    "2024-01-15T10:07:00 WARN firewall Blocked connection from 10.0.0.5",
]

# Parse and analyze
errors = []
for line in log_lines:
    parsed = parse_log_line(line)
    if parsed and parsed["level"] == "ERROR":
        errors.append(parsed)
        print(f"ERROR found: {parsed['message']}")

print(f"\nTotal errors: {len(errors)}")
```

### 3.2 IP Address Validator

```python
import re

def is_valid_ip(ip):
    """Check if a string is a valid IPv4 address."""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)

    if not match:
        return False

    # Check each octet is 0-255
    for group in match.groups():
        if int(group) > 255:
            return False

    return True

def is_private_ip(ip):
    """Check if IP is in private range."""
    if not is_valid_ip(ip):
        return False

    octets = [int(x) for x in ip.split(".")]

    # 10.0.0.0/8
    if octets[0] == 10:
        return True
    # 172.16.0.0/12
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return True

    return False

# Test
ips = ["192.168.1.1", "10.0.0.5", "8.8.8.8", "invalid", "300.1.1.1"]
for ip in ips:
    valid = is_valid_ip(ip)
    private = is_private_ip(ip) if valid else False
    print(f"{ip}: valid={valid}, private={private}")
```

### 3.3 Regular Expressions (Regex) Basics

Regular expressions are patterns used to match text. They're **essential** for security work - IOC extraction, log parsing, and pattern matching all use regex.

#### Why Regex Matters for Security

```python
# Without regex: Manual, error-prone
text = "The malware connects to 192.168.1.100"
# How do you find the IP? Split? Check each word? What about edge cases?

# With regex: One line, handles all cases
import re
ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
# Result: ['192.168.1.100']
```

#### Essential Regex Syntax

| Pattern | Meaning | Example | Matches |
|---------|---------|---------|---------|
| `\d` | Any digit (0-9) | `\d\d\d` | "192", "255", "007" |
| `\w` | Word character (a-z, A-Z, 0-9, _) | `\w+` | "admin", "user_1" |
| `\s` | Whitespace (space, tab, newline) | `\s+` | "   ", "\t\n" |
| `.` | Any character except newline | `a.c` | "abc", "a1c", "a-c" |
| `+` | One or more of previous | `\d+` | "1", "123", "999999" |
| `*` | Zero or more of previous | `\d*` | "", "1", "123" |
| `{n}` | Exactly n of previous | `\d{3}` | "192", "255" (3 digits) |
| `{n,m}` | Between n and m of previous | `\d{1,3}` | "1", "12", "192" |
| `[]` | Character class (any one of) | `[abc]` | "a", "b", or "c" |
| `[^]` | Not in character class | `[^0-9]` | Any non-digit |
| `\b` | Word boundary | `\bcat\b` | "cat" but not "catalog" |
| `^` | Start of string/line | `^Error` | Lines starting with "Error" |
| `$` | End of string/line | `\.exe$` | Strings ending in ".exe" |
| `\|` | Or | `cat\|dog` | "cat" or "dog" |
| `()` | Grouping | `(ab)+` | "ab", "abab", "ababab" |
| `\.` | Literal period (escaped) | `192\.168` | "192.168" literally |

#### Common Security Regex Patterns Explained

```python
import re

# IPv4 Address Pattern
# \d{1,3}  = 1-3 digits
# \.       = literal period (escaped because . means "any char")
# {3}      = repeat previous group 3 times
# \b       = word boundary (so we don't match "1.2.3.4.5.6.7.8")
ipv4_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
# Matches: "192.168.1.1", "10.0.0.5", "8.8.8.8"

# MD5 Hash Pattern (32 hex characters)
# [a-fA-F0-9] = any hex character
# {32}        = exactly 32 of them
md5_pattern = r'\b[a-fA-F0-9]{32}\b'
# Matches: "d41d8cd98f00b204e9800998ecf8427e"

# SHA256 Hash Pattern (64 hex characters)
sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

# Email Pattern
# [A-Za-z0-9._%+-]+  = one or more valid email chars before @
# @                   = literal @
# [A-Za-z0-9.-]+     = domain name
# \.                  = literal period
# [A-Za-z]{2,}       = TLD (2+ letters)
email_pattern = r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

# Domain Pattern
domain_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b'
# Matches: "evil.com", "malware-c2.net"
```

#### Key Regex Functions in Python

```python
import re

text = "Failed login from 192.168.1.100 at 10:30:00"

# re.findall() - Find ALL matches (most common for IOC extraction)
ips = re.findall(r'\d+\.\d+\.\d+\.\d+', text)
print(ips)  # ['192.168.1.100']

# re.search() - Find FIRST match (returns Match object or None)
match = re.search(r'\d{2}:\d{2}:\d{2}', text)
if match:
    print(match.group())  # '10:30:00'

# re.match() - Match at START of string only
if re.match(r'Failed', text):
    print("Starts with 'Failed'")

# re.sub() - Replace matches
cleaned = re.sub(r'\d+\.\d+\.\d+\.\d+', '[REDACTED]', text)
print(cleaned)  # "Failed login from [REDACTED] at 10:30:00"

# re.split() - Split on pattern
parts = re.split(r'\s+', text)  # Split on whitespace
print(parts)  # ['Failed', 'login', 'from', '192.168.1.100', 'at', '10:30:00']
```

#### Common Mistakes

```python
# MISTAKE 1: Forgetting to escape special characters
re.findall(r'192.168.1.1', text)     # BAD: . matches ANY character
re.findall(r'192\.168\.1\.1', text)  # GOOD: \. matches literal period

# MISTAKE 2: Using match() when you want search()
re.match(r'login', "Failed login")   # None! (doesn't start with 'login')
re.search(r'login', "Failed login")  # Match found

# MISTAKE 3: Not using raw strings
pattern = '\d+'    # BAD: Python interprets \d as escape sequence
pattern = r'\d+'   # GOOD: Raw string, regex gets literal \d
```

#### Practice: Build Your Own Patterns

```python
import re

# Practice 1: Extract timestamps (HH:MM:SS format)
log = "Event at 14:30:45 and 09:15:00"
timestamps = re.findall(r'\d{2}:\d{2}:\d{2}', log)
print(timestamps)  # ['14:30:45', '09:15:00']

# Practice 2: Find Windows Event IDs (4-digit numbers after "Event ID:")
log = "Event ID: 4624 - Successful login. Event ID: 4625 - Failed login."
event_ids = re.findall(r'Event ID: (\d{4})', log)  # () captures just the number
print(event_ids)  # ['4624', '4625']

# Practice 3: Extract usernames from log
log = "User 'admin' logged in. User 'john.doe' failed auth."
users = re.findall(r"User '([^']+)'", log)  # [^']+ = anything except quote
print(users)  # ['admin', 'john.doe']
```

> 💡 **Pro Tip**: Use [regex101.com](https://regex101.com/) to test and debug your patterns. It explains what each part does and shows matches in real-time.

---

### 3.4 Simple IOC Extractor

Now let's put regex to work extracting Indicators of Compromise:

```python
import re

def extract_iocs(text):
    """Extract indicators of compromise from text."""
    iocs = {
        "ipv4": [],
        "domains": [],
        "hashes_md5": [],
        "hashes_sha256": [],
        "emails": []
    }

    # IPv4 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    iocs["ipv4"] = list(set(re.findall(ipv4_pattern, text)))

    # Domains (simplified)
    domain_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b'
    iocs["domains"] = list(set(re.findall(domain_pattern, text)))

    # MD5 hashes (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    iocs["hashes_md5"] = list(set(re.findall(md5_pattern, text)))

    # SHA256 hashes (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    iocs["hashes_sha256"] = list(set(re.findall(sha256_pattern, text)))

    # Emails
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    iocs["emails"] = list(set(re.findall(email_pattern, text)))

    return iocs

# Test with sample threat intel
report = """
The malware connects to 192.168.1.100 and evil.com.
It also beacons to 10.0.0.5 every 60 seconds.
File hash: d41d8cd98f00b204e9800998ecf8427e
Contact: analyst@security.org for more info.
"""

iocs = extract_iocs(report)
for ioc_type, values in iocs.items():
    if values:
        print(f"{ioc_type}: {values}")
```

---

## Part 4: Essential Python for ML Labs

These concepts are used heavily in Labs 01-10. Master them here!

### 4.1 List Comprehensions - Concise Loops

List comprehensions are one-line loops. You'll see them everywhere in ML code.

```python
# Traditional loop
filtered_ips = []
for ip in all_ips:
    if ip.startswith("192.168"):
        filtered_ips.append(ip)

# Same thing as list comprehension (preferred in Python)
filtered_ips = [ip for ip in all_ips if ip.startswith("192.168")]

# More examples:
numbers = [1, 2, 3, 4, 5]

# Transform each item
doubled = [n * 2 for n in numbers]  # [2, 4, 6, 8, 10]

# Filter items
evens = [n for n in numbers if n % 2 == 0]  # [2, 4]

# Transform + filter
risky_scores = [score * 1.5 for score in scores if score > 5]

# Security example: Extract IPs from log entries
log_lines = ["ERROR 192.168.1.1 failed", "INFO 10.0.0.5 success", "ERROR 172.16.0.1 failed"]
error_lines = [line for line in log_lines if "ERROR" in line]
# ['ERROR 192.168.1.1 failed', 'ERROR 172.16.0.1 failed']

# Nested comprehension (flatten a list of lists)
nested = [[1, 2], [3, 4], [5, 6]]
flat = [item for sublist in nested for item in sublist]  # [1, 2, 3, 4, 5, 6]
```

### 4.2 Type Hints - Self-Documenting Code

Type hints tell readers (and tools) what types your code expects. Labs 01+ use them throughout.

```python
from typing import List, Dict, Optional, Tuple

# Basic type hints
def calculate_risk(score: int, is_admin: bool) -> float:
    """Type hints show: takes int and bool, returns float."""
    multiplier = 1.5 if is_admin else 1.0
    return score * multiplier

# Collections
def get_suspicious_ips(logs: List[str]) -> List[str]:
    """Takes a list of strings, returns a list of strings."""
    return [line.split()[1] for line in logs if "ERROR" in line]

# Dictionaries
def parse_event(line: str) -> Dict[str, str]:
    """Returns a dictionary with string keys and string values."""
    parts = line.split()
    return {"timestamp": parts[0], "level": parts[1], "message": " ".join(parts[2:])}

# Optional - value might be None
def find_user(user_id: str) -> Optional[Dict]:
    """Returns a dict or None if not found."""
    users = {"alice": {"role": "admin"}, "bob": {"role": "analyst"}}
    return users.get(user_id)  # Returns None if not found

# Tuple - fixed-length, mixed types
def get_stats(data: List[int]) -> Tuple[int, int, float]:
    """Returns (min, max, average) as a tuple."""
    return min(data), max(data), sum(data) / len(data)

# Usage
min_val, max_val, avg = get_stats([1, 2, 3, 4, 5])
```

**Why bother?** 
- IDEs give better autocomplete
- Catch bugs before running
- Code is self-documenting

### 4.3 Pandas Basics - Data Analysis Powerhouse

Labs 01-03 use pandas heavily for data manipulation. Here's what you need to know:

```python
import pandas as pd

# Create a DataFrame (like a spreadsheet)
data = {
    "ip": ["192.168.1.1", "10.0.0.5", "192.168.1.1", "172.16.0.1"],
    "event": ["login", "login", "failed", "login"],
    "user": ["alice", "bob", "alice", "charlie"],
    "risk_score": [2, 5, 8, 3]
}
df = pd.DataFrame(data)

print(df)
#             ip   event     user  risk_score
# 0  192.168.1.1   login    alice           2
# 1     10.0.0.5   login      bob           5
# 2  192.168.1.1  failed    alice           8
# 3   172.16.0.1   login  charlie           3

# Read from CSV (most common)
df = pd.read_csv("alerts.csv")

# Basic operations
print(df.shape)           # (4, 4) - rows, columns
print(df.columns)         # Index(['ip', 'event', 'user', 'risk_score'])
print(df.head(2))         # First 2 rows
print(df.describe())      # Statistics for numeric columns

# Select columns
ips = df["ip"]                        # Single column (Series)
subset = df[["ip", "user"]]           # Multiple columns (DataFrame)

# Filter rows
high_risk = df[df["risk_score"] > 5]  # Rows where risk_score > 5
failed = df[df["event"] == "failed"]  # Rows where event is "failed"

# Multiple conditions (use & for AND, | for OR, wrap in parentheses)
critical = df[(df["risk_score"] > 5) & (df["event"] == "failed")]

# Apply function to column
df["ip_type"] = df["ip"].apply(lambda x: "internal" if x.startswith("192") else "external")

# Group and aggregate
by_user = df.groupby("user")["risk_score"].mean()  # Average risk per user
by_event = df.groupby("event").size()              # Count per event type

# Add new column
df["is_risky"] = df["risk_score"] > 5

# String operations
df["ip_prefix"] = df["ip"].str.split(".").str[0]   # First octet

# Value counts (frequency)
print(df["event"].value_counts())
# login     3
# failed    1

# Save to CSV
df.to_csv("output.csv", index=False)
```

**Pandas cheat sheet for security:**
```python
# Common patterns in the labs
df = pd.read_csv("emails.csv")                     # Load data
df["label"] = df["is_phishing"].map({0: "legit", 1: "phish"})  # Map values
df["text_length"] = df["text"].str.len()           # Feature engineering
X = df[["feature1", "feature2"]]                   # Features for ML
y = df["label"]                                    # Labels for ML
```

### 4.4 Classes - Organizing Complex Code

Labs 04+ use classes to organize related functions. Here's the pattern:

```python
class ThreatAnalyzer:
    """Analyze security events for threats.
    
    Classes group related data (attributes) and functions (methods).
    """
    
    def __init__(self, threshold: float = 0.7):
        """Initialize the analyzer.
        
        __init__ runs when you create an instance.
        self refers to the instance itself.
        """
        self.threshold = threshold
        self.alerts = []
    
    def analyze(self, event: dict) -> dict:
        """Analyze a single event."""
        score = self._calculate_score(event)
        result = {
            "event": event,
            "score": score,
            "is_threat": score > self.threshold
        }
        if result["is_threat"]:
            self.alerts.append(result)
        return result
    
    def _calculate_score(self, event: dict) -> float:
        """Private method (starts with _).
        
        Convention: methods starting with _ are internal.
        """
        score = 0.0
        if event.get("failed_logins", 0) > 3:
            score += 0.5
        if event.get("is_admin", False):
            score += 0.3
        if event.get("after_hours", False):
            score += 0.2
        return min(score, 1.0)
    
    def get_summary(self) -> dict:
        """Get analysis summary."""
        return {
            "total_alerts": len(self.alerts),
            "threshold": self.threshold
        }


# Using the class
analyzer = ThreatAnalyzer(threshold=0.5)  # Create instance

events = [
    {"user": "alice", "failed_logins": 5, "is_admin": True},
    {"user": "bob", "failed_logins": 1, "is_admin": False},
]

for event in events:
    result = analyzer.analyze(event)
    print(f"{event['user']}: score={result['score']:.2f}, threat={result['is_threat']}")

print(analyzer.get_summary())
# alice: score=0.80, threat=True
# bob: score=0.00, threat=False
# {'total_alerts': 1, 'threshold': 0.5}
```

### 4.5 Exception Handling - Graceful Failures

Production code needs to handle errors gracefully:

```python
def safe_parse_log(line: str) -> Optional[dict]:
    """Parse a log line, returning None on failure."""
    try:
        parts = line.strip().split("|")
        return {
            "timestamp": parts[0],
            "level": parts[1],
            "message": parts[2]
        }
    except IndexError:
        print(f"Warning: Malformed log line: {line}")
        return None
    except Exception as e:
        print(f"Error parsing line: {e}")
        return None


def fetch_threat_intel(ip: str) -> dict:
    """Fetch threat intel with proper error handling."""
    import requests
    
    try:
        response = requests.get(f"https://api.example.com/ip/{ip}", timeout=5)
        response.raise_for_status()  # Raises exception for 4xx/5xx
        return response.json()
    except requests.Timeout:
        return {"error": "Request timed out", "ip": ip}
    except requests.HTTPError as e:
        return {"error": f"HTTP error: {e.response.status_code}", "ip": ip}
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}", "ip": ip}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "ip": ip}


# Pattern: Try multiple operations, handle each failure mode
def process_batch(items: List[str]) -> Tuple[List[dict], List[str]]:
    """Process items, separating successes from failures."""
    successes = []
    failures = []
    
    for item in items:
        try:
            result = process_item(item)  # Your processing logic
            successes.append(result)
        except Exception as e:
            failures.append(f"{item}: {e}")
    
    return successes, failures
```

### 4.6 Reading Python Errors (Debugging 101)

When your code breaks, Python shows you an **error message** (traceback). Learning to read these is a superpower!

#### Anatomy of a Traceback

```python
# This code has a bug
def analyze_log(log_entry):
    parts = log_entry.split("|")
    return {"ip": parts[3], "action": parts[4]}

logs = ["2024-01-15|ERROR|Failed login"]
for log in logs:
    result = analyze_log(log)
```

When you run this, Python shows:

```
Traceback (most recent call last):        ← Start of error info
  File "main.py", line 7, in <module>     ← Where error happened (your code)
    result = analyze_log(log)             ← The line that failed
  File "main.py", line 3, in analyze_log  ← Inside the function
    return {"ip": parts[3], "action": parts[4]}  ← The actual problem
IndexError: list index out of range       ← THE ERROR TYPE AND MESSAGE
```

**Reading order**: Start from the BOTTOM!
1. `IndexError: list index out of range` - The error type and message
2. Line 3 - Where in your code it happened
3. `parts[3]` - The operation that failed

**The fix**: The log only has 3 parts (indices 0, 1, 2), but we're asking for index 3 and 4.

#### Common Python Errors and Fixes

| Error | What It Means | Common Causes | Fix |
|-------|---------------|---------------|-----|
| **NameError** | Variable doesn't exist | Typo, not defined yet, wrong scope | Check spelling; define before using |
| **TypeError** | Wrong data type | Using wrong type (string + int) | Convert types: `str()`, `int()` |
| **IndexError** | List index out of range | Accessing index that doesn't exist | Check `len(list)` first |
| **KeyError** | Dict key doesn't exist | Typo in key, key not added | Use `.get(key, default)` |
| **AttributeError** | Object doesn't have that method | Wrong object type | Check what type you have |
| **FileNotFoundError** | File doesn't exist | Wrong path, typo | Check path; use absolute path |
| **IndentationError** | Spaces/tabs wrong | Mixed spaces and tabs | Use consistent indentation |
| **SyntaxError** | Invalid Python syntax | Missing colon, bracket, quote | Check line above error |
| **ModuleNotFoundError** | Import failed | Package not installed | Run `pip install package_name` |
| **ValueError** | Right type, wrong value | e.g., `int("abc")` | Validate input before converting |

#### Examples of Each Error

```python
# NameError - using undefined variable
print(user_name)  # NameError: name 'user_name' is not defined
# Fix: Define it first
user_name = "alice"
print(user_name)

# TypeError - wrong types
"Risk score: " + 85  # TypeError: can only concatenate str to str
# Fix: Convert to string
"Risk score: " + str(85)  # or use f-string: f"Risk score: {85}"

# IndexError - list too short
ips = ["1.1.1.1", "2.2.2.2"]
print(ips[5])  # IndexError: list index out of range
# Fix: Check length first
if len(ips) > 5:
    print(ips[5])

# KeyError - missing dictionary key
event = {"type": "login", "user": "alice"}
print(event["ip"])  # KeyError: 'ip'
# Fix: Use .get() with default
print(event.get("ip", "unknown"))  # Returns "unknown"

# AttributeError - wrong object type
data = None
data.split(",")  # AttributeError: 'NoneType' object has no attribute 'split'
# Fix: Check for None first
if data:
    data.split(",")

# FileNotFoundError - file doesn't exist
with open("missing_file.txt") as f:  # FileNotFoundError
    content = f.read()
# Fix: Check if file exists
from pathlib import Path
if Path("missing_file.txt").exists():
    with open("missing_file.txt") as f:
        content = f.read()
```

#### Debugging Strategies

**1. Print Debugging** - Add prints to see what's happening:

```python
def process_alert(alert):
    print(f"DEBUG: alert = {alert}")           # What did we receive?
    print(f"DEBUG: alert type = {type(alert)}") # What type is it?
    
    severity = alert.get("severity")
    print(f"DEBUG: severity = {severity}")      # What did we get?
    
    if severity > 5:  # This might fail if severity is None
        print("High severity!")
```

**2. Check Types** - Verify you have what you expect:

```python
def analyze(data):
    print(f"Type: {type(data)}")      # Is it a list? dict? string?
    print(f"Length: {len(data)}")      # How many items?
    if isinstance(data, list):
        print(f"First item: {data[0]}")
```

**3. Use AI for Help** - AI assistants are excellent debugging partners:

```
I'm getting this error:

Traceback (most recent call last):
  File "main.py", line 10
    return {"ip": parts[3]}
IndexError: list index out of range

My code is:
[paste your code]

What's wrong and how do I fix it?
```

**AI Prompts for Different Situations:**

| Situation | Prompt Template |
|-----------|-----------------|
| Error message | "Explain this error and how to fix it: [paste error]" |
| Code doesn't work | "My code should [expected], but it [actual]. Here's my code: [paste]" |
| Don't understand code | "Explain this code line by line: [paste code]" |
| Need a better approach | "Is there a better way to [what you're doing]? My current approach: [paste]" |

> 💡 **Pro Tip**: Always include the **full error message**, your **code**, and what you were **trying to do**. The more context you give AI, the better help you'll get.

**4. Isolate the Problem** - Test small pieces:

```python
# Instead of running the whole script, test the function alone:
log = "2024-01-15|ERROR|Failed login"
parts = log.split("|")
print(parts)        # ['2024-01-15', 'ERROR', 'Failed login']
print(len(parts))   # 3 - only indices 0, 1, 2 exist!
```

#### Security-Specific Debugging Tips

```python
# When parsing logs, always validate structure
def parse_log_safely(line):
    parts = line.strip().split("|")
    
    # Validate before accessing
    if len(parts) < 3:
        print(f"Warning: Malformed log (only {len(parts)} parts): {line}")
        return None
    
    return {
        "timestamp": parts[0],
        "level": parts[1],
        "message": parts[2],
        # Use .get() pattern for optional fields
        "extra": parts[3] if len(parts) > 3 else None
    }

# When working with JSON from APIs
import json

def parse_api_response(response_text):
    try:
        data = json.loads(response_text)
        # Safely navigate nested structure
        return data.get("results", {}).get("ip", "unknown")
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        return None
```

---

## Part 5: Making API Requests

### 5.1 Basic HTTP Requests

```python
import requests

# GET request
response = requests.get("https://httpbin.org/ip")
print(f"Status: {response.status_code}")
print(f"Your IP: {response.json()['origin']}")

# GET with parameters
params = {"q": "python security"}
response = requests.get("https://httpbin.org/get", params=params)
print(response.json())

# POST request
data = {"username": "analyst", "action": "login"}
response = requests.post("https://httpbin.org/post", json=data)
print(response.json())
```

### 5.2 API with Authentication

```python
import requests
import os

# API key from environment variable (secure practice)
api_key = os.getenv("VIRUSTOTAL_API_KEY", "your-api-key-here")

# Example: Check IP reputation (pseudo-code - needs real API key)
headers = {
    "x-apikey": api_key
}

# This is an example structure - actual API may differ
def check_ip_reputation(ip):
    """Check IP reputation using an API."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "reputation": data.get("data", {}).get("attributes", {}).get("reputation", "unknown")
            }
        else:
            return {"ip": ip, "error": f"Status {response.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

# Usage (would need real API key)
# result = check_ip_reputation("8.8.8.8")
# print(result)
```

---

## Exercises

### Exercise 1: Failed Login Analyzer
Create a script that:
1. Reads a list of login events
2. Counts failed logins per user
3. Flags users with more than 3 failures

### Exercise 2: IOC Blocklist Generator
Create a script that:
1. Reads IOCs from a text file
2. Validates IP addresses
3. Writes valid IPs to a blocklist file

### Exercise 3: Simple Log Monitor
Create a script that:
1. Reads a log file
2. Extracts all ERROR and WARN messages
3. Groups them by hour
4. Prints a summary

---

## What's Next?

You're ready for:
- **Lab 00b**: ML Concepts Primer - understand machine learning before coding
- **Lab 01**: Phishing Classifier - your first ML security tool

---

## Ready for a Challenge?

Test your Python security skills with a CTF challenge!

After completing this lab, try:
- **[CTF Challenge: Stolen Credentials](../../ctf-challenges/beginner/challenge-01/)** - Parse auth logs to find compromised accounts (100 pts)
- **[CTF Challenge: IOC Extraction](../../ctf-challenges/beginner/challenge-03/)** - Extract indicators from threat intel (100 pts)

Verify your flags with:
```bash
python scripts/verify_flag.py beginner-01 "FLAG{your_answer}"
```

---

## Quick Reference

```python
# Strings
text = "Hello"
text.lower()          # "hello"
text.upper()          # "HELLO"
text.split(",")       # Split into list
"x" in text           # Check if contains

# Lists
items = [1, 2, 3]
items.append(4)       # Add item
items.pop()           # Remove last
len(items)            # Get length
items[0]              # First item
items[-1]             # Last item

# List comprehensions
[x*2 for x in items]              # Transform: [2, 4, 6]
[x for x in items if x > 1]       # Filter: [2, 3]

# Dictionaries
d = {"key": "value"}
d["key"]              # Get value
d.get("key", "default")  # Get with default
d.keys()              # All keys
d.values()            # All values
d.items()             # Key-value pairs

# Files
with open("file.txt", "r") as f:  # Read
with open("file.txt", "w") as f:  # Write
with open("file.txt", "a") as f:  # Append

# Pandas essentials
import pandas as pd
df = pd.read_csv("file.csv")      # Load CSV
df.head()                          # First 5 rows
df[df["col"] > 5]                  # Filter rows
df["col"].apply(func)              # Apply function
df.groupby("col").mean()           # Group & aggregate

# Type hints
from typing import List, Dict, Optional
def func(x: int) -> str:           # Takes int, returns str
def func(items: List[str]) -> Dict[str, int]:

# Exception handling
try:
    risky_operation()
except SpecificError as e:
    handle_error(e)
finally:
    cleanup()

# Common imports
import json           # JSON parsing
import csv            # CSV files
import re             # Regular expressions
import requests       # HTTP requests
import os             # Environment variables
import pandas as pd   # Data analysis
from typing import List, Dict, Optional  # Type hints
```

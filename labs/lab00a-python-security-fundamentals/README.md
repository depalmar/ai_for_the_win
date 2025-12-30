# Lab 00a: Python for Security Fundamentals

Welcome to AI for the Win! This introductory lab teaches Python basics through security-focused examples. No prior programming experience required.

## Learning Objectives

By the end of this lab, you will:
1. Write and run Python scripts
2. Work with strings, lists, and dictionaries
3. Read and write files (logs, CSVs)
4. Make HTTP requests to APIs
5. Parse and analyze security data

## Estimated Time

2-3 hours (take your time!)

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

### 3.3 Simple IOC Extractor

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

## Part 4: Making API Requests

### 4.1 Basic HTTP Requests

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

### 4.2 API with Authentication

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

# Common imports
import json           # JSON parsing
import csv            # CSV files
import re             # Regular expressions
import requests       # HTTP requests
import os             # Environment variables
```

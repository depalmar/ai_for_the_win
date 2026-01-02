# Lab 00a Walkthrough: Python for Security Fundamentals

## Overview

This walkthrough guides you through Python fundamentals using security-focused examples.

**Time to complete walkthrough:** 15 minutes (assumes some coding familiarity)

---

## Step 1: Core Concepts Quick Review

### Variables and Data Types

```python
# Security-relevant data types
ip_address = "192.168.1.100"    # String
port = 443                       # Integer
risk_score = 7.5                 # Float
is_malicious = True              # Boolean

# F-strings for formatting (Python 3.6+)
print(f"Alert: {ip_address}:{port} - Risk: {risk_score}")
```

### Lists and Dictionaries

```python
# List - ordered collection
suspicious_ips = ["10.0.0.5", "192.168.1.100"]
suspicious_ips.append("172.16.0.50")

# Dictionary - key-value pairs
event = {
    "timestamp": "2024-01-15T10:30:00Z",
    "source_ip": "192.168.1.100",
    "severity": "high"
}
print(event["severity"])  # "high"
```

---

## Step 2: Essential Patterns for Security

### Pattern 1: Log Parsing

```python
def parse_log_line(line):
    """Parse a simple log line."""
    parts = line.strip().split(" ")
    return {
        "timestamp": parts[0],
        "level": parts[1],
        "message": " ".join(parts[2:])
    }

# Usage
log = "2024-01-15T10:00:00 ERROR Failed login from 192.168.1.100"
parsed = parse_log_line(log)
```

### Pattern 2: IOC Extraction with Regex

```python
import re

def extract_ips(text):
    """Extract IPv4 addresses from text."""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, text)))

# Usage
report = "Malware connects to 192.168.1.100 and 10.0.0.5"
ips = extract_ips(report)  # ['192.168.1.100', '10.0.0.5']
```

### Pattern 3: Working with Files

```python
import json
import csv

# Read JSON
with open("config.json", "r") as f:
    config = json.load(f)

# Read CSV with pandas (common in ML labs)
import pandas as pd
df = pd.read_csv("alerts.csv")
high_risk = df[df["severity"] == "high"]
```

---

## Step 3: List Comprehensions (Used Everywhere in ML Labs)

```python
# Filter and transform in one line
all_ips = ["192.168.1.1", "10.0.0.5", "8.8.8.8"]

# Filter: only internal IPs
internal = [ip for ip in all_ips if ip.startswith("192.168")]

# Transform: extract first octet
prefixes = [ip.split(".")[0] for ip in all_ips]

# Security example: extract IPs from error logs
logs = ["ERROR 192.168.1.1 failed", "INFO 10.0.0.5 success"]
error_ips = [line.split()[1] for line in logs if "ERROR" in line]
```

---

## Step 4: Type Hints (Modern Python Style)

Labs use type hints for clarity:

```python
from typing import List, Dict, Optional

def calculate_risk(
    failed_logins: int,
    is_admin: bool
) -> float:
    """Type hints document expected types."""
    multiplier = 1.5 if is_admin else 1.0
    return min(failed_logins * multiplier, 10.0)

def parse_events(lines: List[str]) -> List[Dict[str, str]]:
    """Returns list of parsed event dictionaries."""
    return [parse_log_line(line) for line in lines]
```

---

## Step 5: Exception Handling

Production code handles errors gracefully:

```python
def safe_parse(line: str) -> Optional[dict]:
    """Parse log, return None on failure."""
    try:
        parts = line.strip().split("|")
        return {
            "timestamp": parts[0],
            "message": parts[1]
        }
    except IndexError:
        print(f"Warning: Malformed line: {line}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None
```

---

## Step 6: Pandas for Security Data Analysis

Labs 01-03 use pandas heavily:

```python
import pandas as pd

# Load and explore
df = pd.read_csv("security_events.csv")
print(df.shape)           # (rows, columns)
print(df.head())          # First 5 rows
print(df.describe())      # Statistics

# Filter rows
high_severity = df[df["severity"] == "high"]
failed_logins = df[df["event"] == "failed_login"]

# Multiple conditions (use & for AND, | for OR)
critical = df[(df["severity"] == "critical") & (df["user"] == "admin")]

# Group and count
by_user = df.groupby("user").size()
by_event = df["event_type"].value_counts()

# Add new columns
df["is_risky"] = df["risk_score"] > 7
df["ip_prefix"] = df["source_ip"].str.split(".").str[0]
```

---

## Common Errors and Fixes

### Error 1: KeyError in Dictionary

```python
# BAD - crashes if key doesn't exist
value = event["missing_key"]

# GOOD - use .get() with default
value = event.get("missing_key", "N/A")
```

### Error 2: Index Out of Range

```python
# BAD - crashes on short lists
third_item = items[2]

# GOOD - check length first
third_item = items[2] if len(items) > 2 else None
```

### Error 3: File Not Found

```python
# BAD - assumes file exists
with open("data.json") as f:
    data = json.load(f)

# GOOD - handle missing file
from pathlib import Path

if Path("data.json").exists():
    with open("data.json") as f:
        data = json.load(f)
else:
    data = {}
```

---

## Key Takeaways

1. **F-strings** - Use `f"text {variable}"` for formatting
2. **List comprehensions** - `[x for x in items if condition]` is idiomatic Python
3. **Type hints** - Document expected types with `def func(x: int) -> str:`
4. **Error handling** - Always handle exceptions in production code
5. **Pandas** - Essential for data manipulation in ML labs

---

## Quick Reference Card

```python
# Essential imports
import json, csv, re, os
import pandas as pd
from typing import List, Dict, Optional
from pathlib import Path

# String operations
text.lower(), text.upper(), text.strip()
text.split(","), ",".join(items)
"x" in text

# List operations
items.append(x), items.pop(), len(items)
items[0], items[-1], items[1:3]

# Dict operations
d.get("key", default), d.keys(), d.values(), d.items()

# Pandas essentials
df = pd.read_csv("file.csv")
df[df["col"] > 5]                    # Filter
df.groupby("col").size()             # Group
df["new_col"] = df["col"].apply(fn)  # Transform

# File I/O
with open("file.txt", "r") as f:     # Read
with open("file.txt", "w") as f:     # Write
```

---

## Next Lab

Continue to [Lab 00b: ML Concepts Primer](./lab00b-walkthrough.md) to understand machine learning fundamentals before coding.

#!/usr/bin/env python3
"""
Lab 00a: Python for Security Fundamentals - Solution

This is the reference implementation for the lab exercises.
Compare your solutions to learn different approaches.
"""

import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def is_valid_ip(ip_string: str) -> bool:
    """
    Check if a string is a valid IPv4 address.

    Args:
        ip_string: The string to validate

    Returns:
        True if valid IPv4 address, False otherwise
    """
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.match(pattern, ip_string.strip())
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def is_private_ip(ip_string: str) -> bool:
    """
    Check if an IP address is in a private range (RFC 1918).

    Private ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16

    Args:
        ip_string: A valid IPv4 address string

    Returns:
        True if private IP, False if public
    """
    if not is_valid_ip(ip_string):
        return False

    octets = [int(x) for x in ip_string.split(".")]

    # 10.0.0.0/8
    if octets[0] == 10:
        return True
    # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    # 192.168.0.0/16
    if octets[0] == 192 and octets[1] == 168:
        return True

    return False


def parse_log_line(line: str) -> Optional[dict]:
    """
    Parse a log line in the format:
        YYYY-MM-DD HH:MM:SS LEVEL Message

    Args:
        line: A single log line

    Returns:
        Dictionary with timestamp, level, message - or None if parsing fails
    """
    pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (.+)$"
    match = re.match(pattern, line.strip())
    if match:
        return {"timestamp": match.group(1), "level": match.group(2), "message": match.group(3)}
    return None


# ============================================================================
# EXERCISE 1: Failed Login Analyzer - SOLUTION
# ============================================================================


def analyze_failed_logins(filepath: str) -> dict:
    """
    Analyze login events to detect potential brute force attacks.

    This function reads login events and identifies users with excessive
    failed login attempts (more than 3 failures).

    Args:
        filepath: Path to login_events.txt file

    Returns:
        Dictionary with:
            - 'failed_by_user': dict mapping username to failure count
            - 'flagged_users': list of usernames with >3 failures
            - 'total_failures': total number of failed logins
    """
    failed_by_user = defaultdict(int)
    total_failures = 0

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Parse CSV format: timestamp,username,status,ip_address
            parts = line.split(",")
            if len(parts) >= 3:
                username = parts[1]
                status = parts[2]

                if status == "FAILED":
                    failed_by_user[username] += 1
                    total_failures += 1

    # Flag users with more than 3 failures
    flagged_users = [user for user, count in failed_by_user.items() if count > 3]

    return {
        "failed_by_user": dict(failed_by_user),
        "flagged_users": sorted(flagged_users),
        "total_failures": total_failures,
    }


# ============================================================================
# EXERCISE 2: IOC Blocklist Generator - SOLUTION
# ============================================================================


def generate_blocklist(filepath: str, output_path: str) -> dict:
    """
    Process IOC file to extract and validate IP addresses for blocklist.

    This function:
    1. Reads the IOC file
    2. Extracts potential IP addresses
    3. Validates each IP
    4. Excludes private IPs (they shouldn't be in external blocklist)
    5. Writes valid public IPs to output file

    Args:
        filepath: Path to iocs.txt file
        output_path: Path to write the blocklist

    Returns:
        Dictionary with:
            - 'valid_public': list of valid public IPs
            - 'valid_private': list of valid private IPs (not blocked)
            - 'invalid': list of invalid entries
            - 'total_processed': number of lines processed
    """
    valid_public = []
    valid_private = []
    invalid = []
    total_processed = 0

    # IP pattern to extract potential IPs from each line
    ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            total_processed += 1

            # Try to find an IP address in the line
            match = re.search(ip_pattern, line)
            if match:
                ip = match.group(1)

                if is_valid_ip(ip):
                    if is_private_ip(ip):
                        valid_private.append(ip)
                    else:
                        valid_public.append(ip)
                else:
                    invalid.append(line)
            else:
                # Line doesn't contain an IP pattern - check if it looks like
                # a malformed IP attempt
                if re.search(r"\d+\.", line) and not any(c.isalpha() for c in line.split(".")[0]):
                    invalid.append(line)

    # Write valid public IPs to blocklist
    with open(output_path, "w") as f:
        f.write("# Auto-generated blocklist\n")
        f.write(f"# Generated from: {filepath}\n")
        f.write(f"# Valid public IPs: {len(valid_public)}\n\n")
        for ip in sorted(set(valid_public)):
            f.write(f"{ip}\n")

    return {
        "valid_public": sorted(set(valid_public)),
        "valid_private": sorted(set(valid_private)),
        "invalid": invalid,
        "total_processed": total_processed,
    }


# ============================================================================
# EXERCISE 3: Simple Log Monitor - SOLUTION
# ============================================================================


def monitor_logs(filepath: str) -> dict:
    """
    Parse server logs and summarize ERROR and WARN messages by hour.

    This function:
    1. Reads the log file
    2. Parses each line to extract timestamp and level
    3. Groups ERROR and WARN messages by hour
    4. Returns a summary

    Args:
        filepath: Path to server.log file

    Returns:
        Dictionary with:
            - 'by_hour': dict mapping hour to {'ERROR': count, 'WARN': count}
            - 'total_errors': total ERROR count
            - 'total_warnings': total WARN count
            - 'critical_hours': list of hours with more than 2 errors
    """
    by_hour = defaultdict(lambda: {"ERROR": 0, "WARN": 0})
    total_errors = 0
    total_warnings = 0

    with open(filepath, "r") as f:
        for line in f:
            parsed = parse_log_line(line)

            if parsed:
                level = parsed["level"]
                timestamp = parsed["timestamp"]

                # Extract hour from timestamp (format: YYYY-MM-DD HH:MM:SS)
                hour = timestamp.split(" ")[1].split(":")[0]

                if level == "ERROR":
                    by_hour[hour]["ERROR"] += 1
                    total_errors += 1
                elif level == "WARN":
                    by_hour[hour]["WARN"] += 1
                    total_warnings += 1

    # Find critical hours (>2 errors)
    critical_hours = [hour for hour, counts in by_hour.items() if counts["ERROR"] > 2]

    return {
        "by_hour": dict(by_hour),
        "total_errors": total_errors,
        "total_warnings": total_warnings,
        "critical_hours": sorted(critical_hours),
    }


# ============================================================================
# MAIN EXECUTION
# ============================================================================


def main():
    """
    Run all exercises with the provided data files.
    """
    # Get the data directory path
    script_dir = Path(__file__).parent.parent
    data_dir = script_dir / "data"

    print("=" * 60)
    print(" Lab 00a: Python for Security Fundamentals - SOLUTION")
    print("=" * 60)

    # Exercise 1: Failed Login Analyzer
    print("\n" + "-" * 60)
    print(" Exercise 1: Failed Login Analyzer")
    print("-" * 60)
    login_results = analyze_failed_logins(str(data_dir / "login_events.txt"))
    print(f"Total failures: {login_results['total_failures']}")
    print(f"Flagged users (>3 failures): {login_results['flagged_users']}")
    print("Failures by user:")
    for user, count in sorted(login_results["failed_by_user"].items(), key=lambda x: -x[1]):
        flag = " <-- FLAGGED" if count > 3 else ""
        print(f"  {user}: {count} failures{flag}")

    # Exercise 2: IOC Blocklist Generator
    print("\n" + "-" * 60)
    print(" Exercise 2: IOC Blocklist Generator")
    print("-" * 60)
    blocklist_results = generate_blocklist(
        str(data_dir / "iocs.txt"), str(data_dir / "blocklist.txt")
    )
    print(f"Total lines processed: {blocklist_results['total_processed']}")
    print(
        f"Valid public IPs ({len(blocklist_results['valid_public'])}): {blocklist_results['valid_public']}"
    )
    print(
        f"Valid private IPs ({len(blocklist_results['valid_private'])}): {blocklist_results['valid_private']}"
    )
    print(
        f"Invalid entries ({len(blocklist_results['invalid'])}): {blocklist_results['invalid'][:5]}..."
    )

    # Exercise 3: Simple Log Monitor
    print("\n" + "-" * 60)
    print(" Exercise 3: Simple Log Monitor")
    print("-" * 60)
    log_results = monitor_logs(str(data_dir / "server.log"))
    print(f"Total errors: {log_results['total_errors']}")
    print(f"Total warnings: {log_results['total_warnings']}")
    print(f"Critical hours (>2 errors): {log_results['critical_hours']}")
    print("\nBreakdown by hour:")
    for hour, counts in sorted(log_results["by_hour"].items()):
        critical = " <-- CRITICAL" if counts["ERROR"] > 2 else ""
        print(f"  {hour}:00 - Errors: {counts['ERROR']}, Warnings: {counts['WARN']}{critical}")

    print("\n" + "=" * 60)
    print(" All exercises completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()

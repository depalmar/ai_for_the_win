#!/usr/bin/env python3
"""
Lab 00a: Python for Security Fundamentals - Starter Code

This lab teaches Python fundamentals through security-focused exercises.
Complete the three exercises below using the skills from the README.

Exercises:
    1. Failed Login Analyzer - Detect brute force attacks
    2. IOC Blocklist Generator - Validate and filter IP addresses
    3. Simple Log Monitor - Parse and summarize log files
"""

import re
from pathlib import Path
from typing import Optional

# ============================================================================
# HELPER FUNCTIONS (Pre-implemented for you to use)
# ============================================================================


def is_valid_ip(ip_string: str) -> bool:
    """
    Check if a string is a valid IPv4 address.

    Args:
        ip_string: The string to validate

    Returns:
        True if valid IPv4 address, False otherwise

    Example:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("256.1.2.3")
        False
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

    Example:
        >>> parse_log_line("2024-01-15 10:00:00 ERROR Database timeout")
        {'timestamp': '2024-01-15 10:00:00', 'level': 'ERROR', 'message': 'Database timeout'}
    """
    pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (.+)$"
    match = re.match(pattern, line.strip())
    if match:
        return {"timestamp": match.group(1), "level": match.group(2), "message": match.group(3)}
    return None


# ============================================================================
# EXERCISE 1: Failed Login Analyzer
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

    Example output:
        {
            'failed_by_user': {'admin': 6, 'charlie': 2},
            'flagged_users': ['admin'],
            'total_failures': 8
        }

    # TODO: Ask your AI assistant:
    # "Write Python code to read a file line by line, skip comment lines
    # starting with #, parse comma-separated values, count occurrences
    # of 'FAILED' status per username, and flag users with more than 3 failures."
    #
    # Then review and test the generated code.
    """
    # YOUR CODE HERE
    pass


# ============================================================================
# EXERCISE 2: IOC Blocklist Generator
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

    # TODO: Ask your AI assistant:
    # "Write Python code to read a file, extract strings that look like
    # IP addresses, validate them using a regex pattern, classify them as
    # public or private, and write only valid public IPs to an output file."
    #
    # Then review and test the generated code.
    """
    # YOUR CODE HERE
    pass


# ============================================================================
# EXERCISE 3: Simple Log Monitor
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
            - 'by_hour': dict mapping hour (e.g., '10') to {'ERROR': count, 'WARN': count}
            - 'total_errors': total ERROR count
            - 'total_warnings': total WARN count
            - 'critical_hours': list of hours with more than 2 errors

    Example output:
        {
            'by_hour': {
                '09': {'ERROR': 4, 'WARN': 1},
                '10': {'ERROR': 3, 'WARN': 1}
            },
            'total_errors': 7,
            'total_warnings': 2,
            'critical_hours': ['09', '10']
        }

    # TODO: Ask your AI assistant:
    # "Write Python code to parse log files where each line has format
    # 'YYYY-MM-DD HH:MM:SS LEVEL message', extract the hour from timestamp,
    # count ERROR and WARN messages per hour, and identify hours with
    # more than 2 errors."
    #
    # Then review and test the generated code.
    """
    # YOUR CODE HERE
    pass


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
    print(" Lab 00a: Python for Security Fundamentals")
    print("=" * 60)

    # Exercise 1: Failed Login Analyzer
    print("\n" + "-" * 60)
    print(" Exercise 1: Failed Login Analyzer")
    print("-" * 60)
    try:
        login_results = analyze_failed_logins(str(data_dir / "login_events.txt"))
        if login_results:
            print(f"Total failures: {login_results.get('total_failures', 'N/A')}")
            print(f"Flagged users (>3 failures): {login_results.get('flagged_users', [])}")
            print(f"Failures by user: {login_results.get('failed_by_user', {})}")
        else:
            print("Function not yet implemented. Complete the TODO!")
    except Exception as e:
        print(f"Error: {e}")

    # Exercise 2: IOC Blocklist Generator
    print("\n" + "-" * 60)
    print(" Exercise 2: IOC Blocklist Generator")
    print("-" * 60)
    try:
        blocklist_results = generate_blocklist(
            str(data_dir / "iocs.txt"), str(data_dir / "blocklist.txt")
        )
        if blocklist_results:
            print(f"Valid public IPs: {blocklist_results.get('valid_public', [])}")
            print(f"Valid private IPs (excluded): {blocklist_results.get('valid_private', [])}")
            print(f"Invalid entries: {blocklist_results.get('invalid', [])}")
        else:
            print("Function not yet implemented. Complete the TODO!")
    except Exception as e:
        print(f"Error: {e}")

    # Exercise 3: Simple Log Monitor
    print("\n" + "-" * 60)
    print(" Exercise 3: Simple Log Monitor")
    print("-" * 60)
    try:
        log_results = monitor_logs(str(data_dir / "server.log"))
        if log_results:
            print(f"Total errors: {log_results.get('total_errors', 'N/A')}")
            print(f"Total warnings: {log_results.get('total_warnings', 'N/A')}")
            print(f"Critical hours (>2 errors): {log_results.get('critical_hours', [])}")
            print("Breakdown by hour:")
            for hour, counts in sorted(log_results.get("by_hour", {}).items()):
                print(
                    f"  {hour}:00 - Errors: {counts.get('ERROR', 0)}, Warnings: {counts.get('WARN', 0)}"
                )
        else:
            print("Function not yet implemented. Complete the TODO!")
    except Exception as e:
        print(f"Error: {e}")

    print("\n" + "=" * 60)
    print(" Complete the exercises above, then run this script again!")
    print("=" * 60)


if __name__ == "__main__":
    main()

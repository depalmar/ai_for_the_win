#!/usr/bin/env python3
"""
Lab 00h: Vibe Coding with AI Assistants - Solution

Password Strength Analyzer
A complete implementation of the challenge from this lab.

This solution demonstrates what a vibe coding session might produce
after several iterations with an AI assistant.
"""

import argparse
import json
import re
import sys
from typing import Optional

# Common passwords to check against
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "qwerty",
    "login", "abc123", "111111", "admin123", "root",
    "passw0rd", "p@ssword", "password1", "12345678", "123456789",
    "1234567890", "sunshine", "princess", "football", "iloveyou",
    "trustno1", "batman", "access", "shadow", "ashley",
    "michael", "ninja", "mustang", "password!", "hello",
}

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdf", "asdfgh", "zxcv", "zxcvbn",
    "qazwsx", "1qaz", "2wsx", "3edc", "4rfv",
    "1234", "12345", "123456", "4321", "54321",
    "0987", "09876", "7890", "6789",
    "abcd", "bcde", "cdef", "defg",
    "!@#$", "@#$%",
]

# Common character substitutions
SUBSTITUTIONS = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', 'l': 'i',
    '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't',
}


def normalize_substitutions(password: str) -> str:
    """Convert common leetspeak substitutions to letters."""
    normalized = password.lower()
    for sub, char in SUBSTITUTIONS.items():
        normalized = normalized.replace(sub, char)
    return normalized


def check_length(password: str) -> tuple[int, str]:
    """
    Check password length and return score contribution and feedback.

    Returns:
        tuple: (score_points, feedback_message)
    """
    length = len(password)

    if length < 8:
        return 0, f"Password is too short ({length} chars). Use at least 12 characters."
    elif length < 12:
        return 10, f"Password length is weak ({length} chars). Consider using 12+ characters."
    elif length < 16:
        return 20, f"Password length is good ({length} chars)."
    else:
        return 30, f"Excellent password length ({length} chars)!"


def check_character_variety(password: str) -> tuple[int, list[str]]:
    """
    Check for character variety and return score contribution and feedback.

    Returns:
        tuple: (score_points, list_of_feedback_messages)
    """
    score = 0
    feedback = []

    checks = [
        (r'[a-z]', "lowercase letters", 5),
        (r'[A-Z]', "uppercase letters", 10),
        (r'[0-9]', "numbers", 5),
        (r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', "special characters", 10),
    ]

    for pattern, name, points in checks:
        if re.search(pattern, password):
            score += points
        else:
            feedback.append(f"Add {name} to strengthen your password.")

    return score, feedback


def check_common_passwords(password: str) -> tuple[int, str]:
    """
    Check if password is in common password list.

    Checks exact match, case-insensitive, and with substitutions normalized.

    Returns:
        tuple: (score_penalty, feedback_message)
    """
    lower_password = password.lower()
    normalized = normalize_substitutions(password)

    # Check exact match (case-insensitive)
    if lower_password in COMMON_PASSWORDS:
        return -50, "This is an extremely common password. Choose something unique!"

    # Check normalized version (with substitutions)
    if normalized in COMMON_PASSWORDS:
        return -30, "This password is a common password with simple substitutions. Be more creative!"

    # Check if password contains a common password
    for common in COMMON_PASSWORDS:
        if common in lower_password or common in normalized:
            return -15, f"Password contains the common word '{common}'. Avoid common words."

    return 0, ""


def check_patterns(password: str) -> tuple[int, list[str]]:
    """
    Check for weak patterns in the password.

    Detects keyboard walks, repeated characters, and sequential patterns.

    Returns:
        tuple: (score_penalty, list_of_feedback_messages)
    """
    penalty = 0
    feedback = []
    lower_password = password.lower()

    # Check keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower_password:
            penalty -= 10
            feedback.append(f"Avoid keyboard patterns like '{pattern}'.")
            break  # Only penalize once for keyboard patterns

    # Check for repeated characters (3 or more in a row)
    if re.search(r'(.)\1{2,}', password):
        penalty -= 10
        repeated = re.findall(r'(.)\1{2,}', password)
        feedback.append(f"Avoid repeated characters like '{''.join(repeated[0]*3)}'.")

    # Check for sequential numbers
    for seq in ['0123', '1234', '2345', '3456', '4567', '5678', '6789', '9876', '8765', '7654', '6543', '5432', '4321', '3210']:
        if seq in password:
            penalty -= 10
            feedback.append("Avoid sequential numbers.")
            break

    # Check for sequential letters
    for seq in ['abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij', 'dcba', 'edcb', 'fedc', 'gfed', 'hgfe']:
        if seq in lower_password:
            penalty -= 10
            feedback.append("Avoid sequential letters.")
            break

    return penalty, feedback


def check_entropy(password: str) -> tuple[int, str]:
    """
    Estimate password entropy and provide feedback.

    A simple entropy estimation based on character set size and length.

    Returns:
        tuple: (bonus_points, feedback_message)
    """
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        charset_size += 32

    if charset_size == 0:
        return 0, "Unable to calculate entropy."

    import math
    entropy = len(password) * math.log2(charset_size)

    if entropy < 28:
        return 0, f"Entropy is very low (~{entropy:.0f} bits). Easily crackable."
    elif entropy < 36:
        return 5, f"Entropy is low (~{entropy:.0f} bits). Vulnerable to determined attackers."
    elif entropy < 60:
        return 10, f"Entropy is moderate (~{entropy:.0f} bits). Reasonable protection."
    else:
        return 15, f"Entropy is high (~{entropy:.0f} bits). Strong against brute force."


def analyze_password(password: str) -> dict:
    """
    Analyze a password and return detailed results.

    Returns:
        dict: Complete analysis with score, strength, feedback, and details
    """
    score = 0
    all_feedback = []
    details = {}

    # Length check
    length_score, length_feedback = check_length(password)
    score += length_score
    details['length'] = {'score': length_score, 'feedback': length_feedback}
    if length_score < 20:
        all_feedback.append(length_feedback)

    # Character variety check
    variety_score, variety_feedback = check_character_variety(password)
    score += variety_score
    details['variety'] = {'score': variety_score, 'feedback': variety_feedback}
    all_feedback.extend(variety_feedback)

    # Common password check
    common_score, common_feedback = check_common_passwords(password)
    score += common_score
    details['common'] = {'score': common_score, 'feedback': common_feedback}
    if common_feedback:
        all_feedback.append(common_feedback)

    # Pattern check
    pattern_score, pattern_feedback = check_patterns(password)
    score += pattern_score
    details['patterns'] = {'score': pattern_score, 'feedback': pattern_feedback}
    all_feedback.extend(pattern_feedback)

    # Entropy bonus
    entropy_score, entropy_feedback = check_entropy(password)
    score += entropy_score
    details['entropy'] = {'score': entropy_score, 'feedback': entropy_feedback}

    # Ensure score is within bounds
    score = max(0, min(100, score))

    # Get strength label
    strength = get_strength_label(score)

    # Add positive feedback if password is strong
    if not all_feedback:
        all_feedback.append("Great password! No obvious weaknesses detected.")

    return {
        'score': score,
        'strength': strength,
        'feedback': all_feedback,
        'details': details,
        'length': len(password),
    }


def get_strength_label(score: int) -> str:
    """Convert numeric score to strength label."""
    if score < 20:
        return "Very Weak"
    elif score < 40:
        return "Weak"
    elif score < 60:
        return "Fair"
    elif score < 80:
        return "Strong"
    else:
        return "Very Strong"


def get_strength_color(strength: str) -> str:
    """Get ANSI color code for strength level."""
    colors = {
        "Very Weak": "\033[91m",  # Red
        "Weak": "\033[93m",       # Yellow
        "Fair": "\033[33m",       # Orange
        "Strong": "\033[92m",     # Green
        "Very Strong": "\033[96m", # Cyan
    }
    return colors.get(strength, "\033[0m")


def print_results(results: dict, use_color: bool = True) -> None:
    """Print analysis results in a user-friendly format."""
    reset = "\033[0m" if use_color else ""
    bold = "\033[1m" if use_color else ""

    strength = results['strength']
    color = get_strength_color(strength) if use_color else ""

    # Header
    print(f"\n{bold}Password Strength Analysis{reset}")
    print("=" * 40)

    # Score and strength
    print(f"\nScore: {color}{results['score']}/100{reset}")
    print(f"Strength: {color}{strength}{reset}")
    print(f"Length: {results['length']} characters")

    # Progress bar
    filled = int(results['score'] / 5)
    bar = "█" * filled + "░" * (20 - filled)
    print(f"\n[{color}{bar}{reset}]")

    # Feedback
    print(f"\n{bold}Feedback:{reset}")
    for item in results['feedback']:
        prefix = "✓" if "Great" in item or "Excellent" in item else "→"
        print(f"  {prefix} {item}")

    # Detailed breakdown
    print(f"\n{bold}Score Breakdown:{reset}")
    for check, data in results['details'].items():
        score_str = f"+{data['score']}" if data['score'] >= 0 else str(data['score'])
        print(f"  {check.capitalize()}: {score_str} points")

    print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze password strength and provide improvement suggestions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "MyP@ssw0rd123"
  echo "secretpassword" | %(prog)s
  %(prog)s --json "TestPassword"
        """
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to analyze (or read from stdin if not provided)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    # Get password from argument or stdin
    if args.password:
        password = args.password
    elif not sys.stdin.isatty():
        password = sys.stdin.read().strip()
    else:
        # Interactive mode - hide input
        import getpass
        password = getpass.getpass("Enter password to analyze: ")

    if not password:
        print("Error: No password provided", file=sys.stderr)
        sys.exit(1)

    # Analyze the password
    results = analyze_password(password)

    # Output results
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_results(results, use_color=not args.no_color)

    # Exit with appropriate code
    sys.exit(0 if results['score'] >= 60 else 1)


if __name__ == "__main__":
    main()

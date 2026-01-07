#!/usr/bin/env python3
"""
Lab 00h: Vibe Coding with AI Assistants - Starter Template

This is a skeleton for the Password Strength Analyzer challenge.
Use your AI coding assistant to fill in the implementation!

Challenge: Build a password strength analyzer that:
1. Accepts a password via CLI argument or stdin
2. Analyzes strength based on multiple criteria
3. Provides specific improvement suggestions
4. Scores the password from 0-100
"""

import argparse
import re
import sys

# Common passwords to check against (expand this list or load from file)
COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "qwerty",
    "login", "abc123", "111111", "admin123", "root",
    # TODO: Add more common passwords or load from a file
]

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx",
    "1234", "4321", "0987", "7890",
    # TODO: Add more keyboard walk patterns
]


def check_length(password: str) -> tuple[int, str]:
    """
    Check password length and return score contribution and feedback.

    Scoring guide:
    - Less than 8 chars: 0 points (critical)
    - 8-11 chars: 10 points (weak)
    - 12-15 chars: 20 points (good)
    - 16+ chars: 30 points (excellent)

    TODO: Implement this function with your AI assistant
    """
    # YOUR CODE HERE
    pass


def check_character_variety(password: str) -> tuple[int, list[str]]:
    """
    Check for character variety and return score contribution and feedback.

    Check for presence of:
    - Lowercase letters (a-z)
    - Uppercase letters (A-Z)
    - Numbers (0-9)
    - Special characters (!@#$%^&*...)

    Each category present adds points to the score.

    TODO: Implement this function with your AI assistant
    """
    # YOUR CODE HERE
    pass


def check_common_passwords(password: str) -> tuple[int, str]:
    """
    Check if password is in common password list.

    Should check:
    - Exact matches
    - Case-insensitive matches
    - Common substitutions (@ for a, 3 for e, etc.)

    TODO: Implement this function with your AI assistant
    """
    # YOUR CODE HERE
    pass


def check_patterns(password: str) -> tuple[int, list[str]]:
    """
    Check for weak patterns in the password.

    Detect:
    - Keyboard walks (qwerty, asdf, etc.)
    - Repeated characters (aaa, 111)
    - Sequential characters (abc, 123)

    TODO: Implement this function with your AI assistant
    """
    # YOUR CODE HERE
    pass


def analyze_password(password: str) -> dict:
    """
    Analyze a password and return detailed results.

    Returns a dict with:
    - score: 0-100 overall score
    - strength: "Very Weak", "Weak", "Fair", "Strong", "Very Strong"
    - feedback: list of improvement suggestions
    - details: breakdown of individual checks

    TODO: Implement this function by combining the check functions above
    """
    # YOUR CODE HERE
    pass


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


def print_results(results: dict) -> None:
    """
    Print analysis results in a user-friendly format.

    TODO: Implement nice formatting with your AI assistant
    """
    # YOUR CODE HERE
    pass


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze password strength and provide improvement suggestions"
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
        password = input("Enter password to analyze: ")

    # Analyze the password
    results = analyze_password(password)

    # Output results
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    else:
        print_results(results)


if __name__ == "__main__":
    main()

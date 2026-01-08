#!/usr/bin/env python3
"""
XQL Validator CLI
Command-line interface for validating XQL queries.
"""

import argparse
import sys
from pathlib import Path

from .validator import XQLValidator, Severity, validate_file, validate_query


def main():
    parser = argparse.ArgumentParser(
        description="Validate Cortex XDR XQL query syntax",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a query from stdin
  echo "| dataset = xdr_data | filter event_type = ENUM.PROCESS" | python -m xql_validator

  # Validate a file
  python -m xql_validator queries.xql

  # Validate multiple files
  python -m xql_validator *.xql

  # Show only errors (no warnings/info)
  python -m xql_validator --errors-only queries.xql
        """,
    )

    parser.add_argument(
        "files",
        nargs="*",
        help="XQL files to validate (reads from stdin if not provided)",
    )
    parser.add_argument(
        "--errors-only",
        action="store_true",
        help="Only show errors, not warnings or info",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only output if issues found",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    exit_code = 0
    all_results = []

    if args.files:
        # Validate files
        for file_path in args.files:
            is_valid, issues = validate_file(file_path)
            if args.errors_only:
                issues = [i for i in issues if i.severity == Severity.ERROR]

            if not is_valid:
                exit_code = 1

            if args.json:
                all_results.append(
                    {
                        "file": file_path,
                        "valid": is_valid,
                        "issues": [
                            {
                                "line": i.line,
                                "column": i.column,
                                "severity": i.severity.value,
                                "code": i.code,
                                "message": i.message,
                                "suggestion": i.suggestion,
                            }
                            for i in issues
                        ],
                    }
                )
            elif issues or not args.quiet:
                print(f"\n=== {file_path} ===")
                if issues:
                    validator = XQLValidator()
                    validator.issues = issues
                    print(validator.format_issues())
                else:
                    print("No issues found.")
    else:
        # Read from stdin
        query = sys.stdin.read()
        is_valid, issues = validate_query(query)

        if args.errors_only:
            issues = [i for i in issues if i.severity == Severity.ERROR]

        if not is_valid:
            exit_code = 1

        if args.json:
            import json

            all_results.append(
                {
                    "file": "<stdin>",
                    "valid": is_valid,
                    "issues": [
                        {
                            "line": i.line,
                            "column": i.column,
                            "severity": i.severity.value,
                            "code": i.code,
                            "message": i.message,
                            "suggestion": i.suggestion,
                        }
                        for i in issues
                    ],
                }
            )
        elif issues or not args.quiet:
            validator = XQLValidator()
            validator.issues = issues
            print(validator.format_issues())

    if args.json:
        import json

        print(json.dumps(all_results, indent=2))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

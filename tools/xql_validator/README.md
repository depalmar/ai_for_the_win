# XQL Query Validator

A Python-based syntax checker for Cortex XDR XQL queries.

## Features

- Validates XQL query syntax
- Checks for common mistakes (wrong function names, field names)
- Warns about missing best practices (time filtering, limits)
- Supports file and stdin input
- JSON output for CI/CD integration

## Installation

The validator is included in the repository. No additional installation needed.

```bash
# From repository root
cd tools/xql_validator
```

## Usage

### Command Line

```bash
# Validate a query from stdin
echo "| dataset = xdr_data | filter event_type = ENUM.PROCESS" | python -m xql_validator

# Validate a file
python -m xql_validator path/to/queries.xql

# Validate multiple files
python -m xql_validator templates/xql/*.xql

# Show only errors (no warnings)
python -m xql_validator --errors-only queries.xql

# Output as JSON
python -m xql_validator --json queries.xql
```

### Python API

```python
from tools.xql_validator import validate_query, validate_file, XQLValidator

# Validate a query string
query = """
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
| filter length(actor_process_command_line) > 100
"""

is_valid, issues = validate_query(query)
print(f"Valid: {is_valid}")

for issue in issues:
    print(f"[{issue.severity.value}] Line {issue.line}: {issue.message}")

# Validate a file
is_valid, issues = validate_file("queries.xql")
```

## Validation Rules

### Errors (E)

| Code | Description |
|------|-------------|
| E001 | Unknown stage name |
| E002 | Mismatched parentheses |
| E003 | Unclosed string quote |
| E999 | File not found |

### Warnings (W)

| Code | Description |
|------|-------------|
| W001 | Common function name mistake (e.g., `length` vs `strlen`) |
| W002 | Missing dataset or preset declaration |

### Info (I)

| Code | Description |
|------|-------------|
| I001 | Query may benefit from time filtering |
| I002 | Query missing LIMIT clause |

## Common Mistakes Detected

| Wrong | Correct |
|-------|---------|
| `length()` | `strlen()` |
| `array_length()` | `arraylen()` |
| `extract_time()` | `timestamp_extract()` |
| `event_type = "PROCESS"` | `event_type = ENUM.PROCESS` |
| `agent_ip` | `agent_ip_addresses` |
| `action_dns_query_name` | `dns_query_name` |

## CI/CD Integration

Use the JSON output for automated validation:

```yaml
# GitHub Actions example
- name: Validate XQL
  run: |
    python -m xql_validator --json --errors-only templates/xql/*.xql > validation.json
    if [ $? -ne 0 ]; then
      echo "XQL validation failed"
      cat validation.json
      exit 1
    fi
```

## Extending

Add new validation rules by modifying `validator.py`:

1. Add patterns to `COMMON_MISTAKES` for new common errors
2. Add to `VALID_FUNCTIONS` or `VALID_STAGES` as XQL evolves
3. Add new check methods and call them from `_check_line` or `_check_query_structure`

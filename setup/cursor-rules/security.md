# Security Requirements (CRITICAL)

## Data Handling

- NEVER log sensitive data (API keys, credentials, PII)
- NEVER commit .env files or secrets
- ALWAYS use environment variables for API keys
- ALWAYS validate external inputs

## IOC Handling (Indicators of Compromise)

When outputting IOCs, ALWAYS defang them:

| Type | Original | Defanged |
|------|----------|----------|
| URL | `http://` | `hxxp://` |
| URL | `https://` | `hxxps://` |
| Domain | `example.com` | `example[.]com` |
| IP | `192.168.1.1` | `192[.]168[.]1[.]1` |

## Malware Analysis Context

When analyzing potentially malicious code:

1. Explain what the code does in detail
2. Map to MITRE ATT&CK techniques (e.g., T1059.001)
3. Extract all IOCs
4. Provide detection recommendations
5. NEVER enhance or weaponize malicious functionality

## Security References

Always include relevant references:

- **MITRE ATT&CK**: T1059.001, T1055, etc.
- **CVE IDs**: CVE-2024-1234
- **CWE**: CWE-89 (SQL Injection)

## Input Validation

- Validate file paths to prevent traversal
- Use parameterized queries (no string formatting)
- Escape output in web contexts
- Never trust user-provided filenames

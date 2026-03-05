# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.9.x   | :white_check_mark: |
| < 1.9   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/) via LinkedIn with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix or mitigation** within 30 days for confirmed vulnerabilities
- Credit in the changelog (unless you prefer anonymity)

### Scope

**In scope:**
- Code in `shared/`, `scripts/`, `mcp-servers/`
- GitHub Actions workflows
- Docker configurations
- Dependency vulnerabilities in `requirements.txt` and `pyproject.toml`

**Out of scope (intentional for training):**
- Vulnerabilities in `ctf-challenges/` — these are intentional for educational exercises
- Vulnerable dependencies in `labs/*/data/` sample files
- IOCs (Indicators of Compromise) in lab data — these are defanged/fictional

## Security Practices

This project follows these security practices:

- **Dependency scanning**: Dependabot alerts enabled, reviewed weekly
- **Code scanning**: CodeQL analysis on every PR
- **OpenSSF Scorecard**: Monitored via GitHub Actions
- **Pinned dependencies**: GitHub Actions use SHA-pinned versions; Docker images use digest pins
- **Secrets**: No hardcoded secrets; `.env.example` templates only
- **SBOM**: Software Bill of Materials generated on each release

## Dependencies

We monitor dependencies via:
- GitHub Dependabot (automated PRs for vulnerable dependencies)
- `safety check` in CI pipeline
- `bandit` static analysis for Python security issues
- OpenSSF Scorecard for supply chain security

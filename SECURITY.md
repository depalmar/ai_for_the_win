# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously in this educational project. If you discover a security vulnerability, please follow responsible disclosure practices:

### Do NOT

- Open a public GitHub issue for security vulnerabilities
- Share vulnerability details publicly before a fix is available
- Include real malware samples in bug reports

### Do

1. **Email the maintainers directly** with details of the vulnerability
2. **Include the following information:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (if available)
3. **Allow reasonable time** for us to investigate and address the issue
4. **Coordinate disclosure** with us before making any public announcements

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Updates**: We will provide updates on our progress within 7 days
- **Resolution**: We aim to resolve critical issues within 30 days
- **Credit**: We will credit you in our release notes (unless you prefer to remain anonymous)

## Security Considerations for This Project

### Educational Nature

This repository is designed for **educational purposes**. The labs teach security concepts including:

- Malware analysis techniques
- Threat detection methods
- Adversarial ML concepts
- LLM security testing

### Safe Practices Enforced

1. **No Real Malware**: All malware samples are simulated/synthetic
2. **Safe Simulation Mode**: Purple team labs (Lab 12) have safety controls
3. **No Credential Storage**: API keys use environment variables, never committed
4. **Input Validation**: Labs demonstrate proper input validation techniques

### For Lab Users

When working through the labs:

- **Never use real malware** - stick to provided sample data
- **Keep API keys secure** - use `.env` files (gitignored)
- **Use test environments** - don't run detection labs against production systems
- **Respect rate limits** - avoid API abuse

### Dependencies

We regularly update dependencies to address known vulnerabilities:

```bash
# Check for vulnerable dependencies
pip-audit

# Update dependencies
pip install --upgrade -r requirements.txt
```

## Security Features

### Pre-commit Hooks

This repository includes security checks via pre-commit:

- **Bandit**: Python security linter
- **Private key detection**: Prevents accidental key commits
- **YAML validation**: Catches configuration issues

### CI/CD Security

- Automated dependency scanning via Dependabot
- Security-focused code review requirements
- No secrets in CI logs

## Scope

The following are **in scope** for security reports:

- Vulnerabilities in lab code that could affect learners
- Issues with sample data that could cause harm
- CI/CD pipeline security issues
- Documentation that encourages unsafe practices

The following are **out of scope**:

- Theoretical attacks that require physical access
- Social engineering attacks
- Issues in third-party dependencies (report to upstream)
- Educational content describing attack techniques (this is intentional)

## Contact

For security concerns, please use the GitHub Security Advisory feature or contact the maintainers through GitHub.

---

Thank you for helping keep AI for the Win secure! 🛡️

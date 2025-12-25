# Security Policy

## Reporting a Vulnerability

We take the security of AI for the Win seriously. If you discover a security vulnerability, please follow these steps:

### How to Report

**Please DO NOT open a public issue for security vulnerabilities.**

Instead, please report security vulnerabilities by:

1. **Email**: Send details to the repository owner via GitHub
2. **GitHub Security Advisories**: Use the "Security" tab → "Report a vulnerability"

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and attack scenarios
- **Reproduction Steps**: Detailed steps to reproduce the issue
- **Proof of Concept**: Code snippets or screenshots (if applicable)
- **Suggested Fix**: If you have recommendations (optional)
- **Environment**: OS, Python version, affected components

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 1-3 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Best effort

## Security Best Practices for Users

### API Keys and Secrets

This project requires API keys for various services (Anthropic Claude, OpenAI, etc.). **Never commit API keys to the repository.**

**Proper handling:**
- Use `.env` files (see `.env.example`)
- Add `.env` to `.gitignore` (already configured)
- Use environment variables in production
- Rotate keys regularly

### Lab Exercises

Many labs involve security tools and techniques:

1. **Sandboxed Environment**: Run labs in isolated environments
2. **Malware Samples**: Use only the provided synthetic samples
3. **Network Scanning**: Only scan your own networks/systems
4. **Ethical Use**: Follow responsible disclosure practices
5. **Legal Compliance**: Ensure you have authorization for any testing

### Docker Security

If using Docker containers:
- Keep base images updated
- Don't run containers as root (configured in Dockerfile)
- Review Docker Compose configurations
- Scan images for vulnerabilities: `docker scan`

## Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| main    | :white_check_mark: | Latest development version |
| v1.x    | :white_check_mark: | Current stable release |
| < 1.0   | :x:                | No longer supported |

## Security Features

### Dependency Scanning

- **Dependabot**: Automated dependency updates
- **Safety Check**: Python package vulnerability scanning (in CI)
- **Bandit**: Static security analysis for Python code

### Code Security

- **Pre-commit Hooks**: Automated security checks (`.pre-commit-config.yaml`)
- **Secret Scanning**: GitHub secret detection (enable in Settings)
- **CodeQL Analysis**: Automated code scanning (see `.github/workflows/codeql.yml`)

### CI/CD Security

All pull requests are automatically scanned for:
- Known vulnerabilities in dependencies
- Security anti-patterns in code
- Potential secrets in commits
- Syntax errors in lab solutions

## Known Security Considerations

### Training Data

This repository contains:
- Synthetic malware samples (JSON representations, not actual malware)
- Sample phishing emails (for training purposes)
- Mock security logs and events

**These are for educational purposes only and should not be used maliciously.**

### API Usage

Labs make API calls to external services:
- Rate limiting is implemented
- API keys should use least-privilege access
- Monitor API usage for unexpected patterns

### LLM Security

When working with LLM labs:
- Be aware of prompt injection risks
- Validate and sanitize all inputs
- Don't send sensitive data to external LLMs
- Review LLM outputs before executing code

## Responsible Disclosure

We follow coordinated vulnerability disclosure:

1. **Private Disclosure**: Report to maintainers first
2. **Acknowledgment**: We'll acknowledge receipt within 48 hours
3. **Investigation**: We'll investigate and develop a fix
4. **Coordination**: We'll work with you on disclosure timing
5. **Public Disclosure**: After fix is released and users have time to update
6. **Credit**: Reporter will be credited (unless they prefer anonymity)

## Security Hall of Fame

We appreciate security researchers who help keep this project secure. Contributors who responsibly disclose vulnerabilities will be acknowledged here (with permission):

- *No vulnerabilities reported yet*

## Contact

- **GitHub Issues**: For general bugs (non-security)
- **GitHub Security**: For vulnerability reports
- **Email**: Contact via GitHub profile

## License

This security policy is licensed under CC BY 4.0.

---

**Last Updated**: December 2025

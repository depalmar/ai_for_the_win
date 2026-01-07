# Challenge 06: Supply Chain Detective

**Category:** Supply Chain Security
**Points:** 500
**Difficulty:** Advanced

## Description

A development team discovered suspicious behavior in their CI/CD pipeline. Someone may have injected malicious code through a compromised dependency. Your task is to analyze the project's dependency files, package metadata, and installation logs to identify the malicious package.

Your mission: Find the supply chain compromise and extract the flag hidden by the attacker.

## Objective

1. Analyze Python and Node.js dependency files
2. Compare package versions against known-good baselines
3. Examine package metadata for anomalies
4. Identify typosquatting or malicious packages
5. Find the flag in the attacker's payload

## Files

- `requirements.txt` - Python dependencies
- `package.json` - Node.js dependencies
- `package_metadata.json` - Detailed package information from registries
- `pip_install_log.txt` - Output from pip installation
- `baseline_versions.json` - Known-good package versions

## Background

Supply chain attacks target the software development process by:
- **Typosquatting**: Creating packages with similar names (e.g., `requests` vs `reqeusts`)
- **Dependency Confusion**: Publishing malicious internal package names publicly
- **Version Manipulation**: Compromising specific versions of legitimate packages
- **Maintainer Compromise**: Taking over abandoned or vulnerable packages

## Rules

- Analyze all dependency files
- The flag format is `FLAG{...}`
- Compare against baselines carefully

## Hints

<details>
<summary>Hint 1 (costs 50 pts)</summary>

One package name is very similar to a popular package but has a subtle misspelling.

</details>

<details>
<summary>Hint 2 (costs 100 pts)</summary>

Check the package metadata for unusual installation scripts or maintainer information.

</details>

<details>
<summary>Hint 3 (costs 150 pts)</summary>

The malicious package's post-install script contains the flag in base64 encoding.

</details>

## Skills Tested

- Software supply chain security
- Dependency analysis
- Typosquatting detection
- Package registry investigation
- AI-assisted code review

## Submission

```bash
python ../../../scripts/verify_flag.py advanced-06 "FLAG{your_answer}"
```

Secure the supply chain! 📦

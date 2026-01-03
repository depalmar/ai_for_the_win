# Contributing to AI for the Win

Thank you for your interest in contributing to the AI Security Training Program! This document provides guidelines for contributing.

> **Note**: This is a personal educational project not affiliated with any employer or vendor. Contributions should remain vendor-neutral and focused on educational value.

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTRIBUTION WORKFLOW                     │
│                                                             │
│   1. Fork ──► 2. Branch ──► 3. Code ──► 4. Test ──► 5. PR  │
│      │           │            │           │           │     │
│      ▼           ▼            ▼           ▼           ▼     │
│   [Your      [feature/    [Make      [pytest]    [Submit   │
│    Copy]      name]        edits]                 Review]   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the technical merits of contributions
- Follow responsible disclosure for any security issues

## Areas for Contribution

We welcome contributions in these areas:

| Area | Description | Difficulty |
|------|-------------|------------|
| **Labs** | Add new labs, improve existing solutions | Medium-Hard |
| **Data** | Sample datasets, test cases | Easy-Medium |
| **Documentation** | Fix typos, improve clarity | Easy |
| **Templates** | Agent templates, integrations | Medium |
| **Tests** | Expand test coverage | Medium |
| **Capstones** | Project ideas, starter code | Hard |

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use the appropriate issue template
3. Provide clear reproduction steps for bugs
4. Include environment details (Python version, OS, etc.)

### Submitting Changes

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test your changes**
   ```bash
   pytest tests/
   ```
5. **Submit a pull request**

### Pull Request Guidelines

- Write clear, descriptive commit messages
- Include tests for new functionality
- Update documentation as needed
- Ensure CI checks pass
- Reference related issues in the PR description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ai_for_the_win.git
cd ai_for_the_win

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install pre-commit hooks (recommended)
pip install pre-commit
pre-commit install

# Run tests to verify setup
pytest tests/ -v
```

### Pre-commit Hooks

This repository includes a `.pre-commit-config.yaml` with the following checks:
- **Black** - Code formatting
- **isort** - Import sorting
- **Flake8** - Linting with bugbear and comprehensions
- **Bandit** - Security scanning
- **General checks** - Trailing whitespace, YAML validation, private key detection
- **Markdownlint** - Markdown formatting

Pre-commit runs automatically on `git commit`. To run manually:

```bash
# Run on all files
pre-commit run --all-files

# Run specific hook
pre-commit run black --all-files
```

## Code Style

### Python

- Follow PEP 8 style guidelines
- Use type hints for function parameters and returns
- Maximum line length: 100 characters
- Use descriptive variable and function names

```python
# Good
def analyze_malware_sample(file_path: str, timeout: int = 30) -> dict:
    """Analyze a malware sample and return results."""
    pass

# Bad
def analyze(f, t=30):
    pass
```

### Formatting

Run before committing:

```bash
# Format code
black .

# Check linting
flake8 .

# Type checking
mypy .
```

## Lab Contributions

### Adding New Labs

1. Create lab directory: `labs/labXX-name/`
2. Include required files:
   ```
   labXX-name/
   ├── README.md          # Lab instructions
   ├── starter/
   │   └── main.py        # Starter code with TODOs
   ├── solution/
   │   └── main.py        # Complete solution
   ├── data/              # Sample data files
   └── tests/
       └── test_main.py   # Unit tests
   ```
3. Follow existing lab format and style
4. Include clear learning objectives
5. Provide sample data that doesn't contain real malware

### Lab README Template

```markdown
# Lab XX: Title

Brief description of the lab.

## Learning Objectives

1. Objective 1
2. Objective 2

## Estimated Time

XX-XX minutes

## Prerequisites

- Required prior knowledge
- Required libraries

## Background

Educational context...

## Tasks

### Task 1: Task Name (XX min)

Instructions...

## Success Criteria

- [ ] Criterion 1
- [ ] Criterion 2

## Resources

- [Resource 1](url)
```

## Security Considerations

### Handling Malware Samples

- **NEVER** include real malware in the repository
- Use simulated/synthetic data for labs
- Document any potentially dangerous code clearly
- Include appropriate warnings in documentation

### API Keys and Secrets

- **NEVER** commit API keys or secrets
- Use environment variables for configuration
- Include `.env.example` files with placeholder values
- Document required environment variables

### Responsible Disclosure

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email the maintainers directly
3. Allow time for a fix before disclosure
4. Follow coordinated disclosure practices

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=labs --cov-report=html

# Run specific lab tests
pytest labs/lab01-phishing-classifier/tests/
```

### Writing Tests

```python
import pytest
from solution.main import function_to_test

def test_function_basic():
    """Test basic functionality."""
    result = function_to_test("input")
    assert result == expected_output

def test_function_edge_case():
    """Test edge case handling."""
    with pytest.raises(ValueError):
        function_to_test(None)
```

## Documentation

### Markdown Style

- Use ATX-style headers (`#`, `##`, etc.)
- Include code blocks with language specification
- Use tables for structured data
- Add alt text for images

### Code Comments

- Document complex algorithms
- Explain security-relevant code sections
- Keep comments up-to-date with code changes

## Review Process

1. All PRs require at least one review
2. CI checks must pass
3. Documentation must be updated
4. Tests must be included for new code

## Recognition

Contributors will be recognized in:
- The project README
- Release notes for significant contributions
- The contributors page (if created)

## Questions?

- Open a discussion on GitHub
- Check existing documentation
- Review closed issues for similar questions

---

Thank you for contributing to AI for the Win!

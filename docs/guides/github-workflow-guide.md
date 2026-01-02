# GitHub Workflow Guide

Complete guide to using GitHub for AI security tool development and collaboration.

---

## 📋 Table of Contents

1. [Setup & Configuration](#setup--configuration)
2. [Repository Management](#repository-management)
3. [GitHub CLI](#github-cli)
4. [Branching Strategy](#branching-strategy)
5. [Pull Requests & Code Review](#pull-requests--code-review)
6. [GitHub Actions for Security](#github-actions-for-security)
7. [Security Best Practices](#security-best-practices)
8. [Collaboration Workflows](#collaboration-workflows)

---

## ⚙️ Setup & Configuration

### Git Installation

```bash
# Windows (via winget)
winget install Git.Git

# macOS (via Homebrew)
brew install git

# Linux (Debian/Ubuntu)
sudo apt install git
```

### Initial Configuration

```bash
# Set your identity
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Set default branch name
git config --global init.defaultBranch main

# Set default editor
git config --global core.editor "code --wait"  # VS Code/Cursor

# Enable credential caching
git config --global credential.helper cache
git config --global credential.helper 'cache --timeout=3600'

# Useful aliases
git config --global alias.st status
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.lg "log --oneline --graph --all --decorate"
git config --global alias.unstage "reset HEAD --"
git config --global alias.last "log -1 HEAD"
```

### SSH Key Setup

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your.email@example.com"

# Start SSH agent
eval "$(ssh-agent -s)"

# Add key to agent
ssh-add ~/.ssh/id_ed25519

# Copy public key
cat ~/.ssh/id_ed25519.pub
# Add this to GitHub: Settings > SSH and GPG keys > New SSH key

# Test connection
ssh -T git@github.com
```

### GPG Commit Signing (Optional but Recommended)

```bash
# Generate GPG key
gpg --full-generate-key

# List keys
gpg --list-secret-keys --keyid-format=long

# Get key ID (the part after 'sec   rsa4096/')
# Example: sec   rsa4096/3AA5C34371567BD2

# Tell Git about your key
git config --global user.signingkey 3AA5C34371567BD2
git config --global commit.gpgsign true

# Add to GitHub: Settings > SSH and GPG keys > New GPG key
gpg --armor --export 3AA5C34371567BD2
```

---

## 📁 Repository Management

### Creating a New Repository

```bash
# Initialize locally
mkdir my-security-tool && cd my-security-tool
git init

# Create essential files
touch README.md .gitignore LICENSE

# Add content to .gitignore
cat << 'EOF' > .gitignore
# Python
__pycache__/
*.py[cod]
.venv/
venv/

# Environment
.env
.env.local

# IDE
.idea/
.vscode/
.cursor/

# Security - Never commit
*.pem
*.key
secrets/
credentials/
samples/malware/
EOF

# Initial commit
git add .
git commit -m "feat: Initial project setup"

# Create on GitHub and push
gh repo create my-security-tool --public --source=. --push
```

### Cloning Existing Repository

```bash
# HTTPS
git clone https://github.com/username/repo.git

# SSH (recommended)
git clone git@github.com:username/repo.git

# With specific branch
git clone -b develop git@github.com:username/repo.git

# Shallow clone (faster for large repos)
git clone --depth 1 git@github.com:username/repo.git
```

### .gitignore for Security Projects

```gitignore
# ===== Security-Specific =====
# Never commit these!
*.pem
*.key
*.crt
*.p12
.env
.env.*
secrets/
credentials/
api_keys/

# Malware samples (dangerous!)
samples/
malware/
*.exe
*.dll
*.bin
*.dump
*.vmem
*.raw

# Memory dumps
*.dmp
*.mem

# ===== Python =====
__pycache__/
*.py[cod]
*$py.class
.venv/
venv/
*.egg-info/
dist/
build/

# ===== ML/AI =====
*.h5
*.pkl
*.pt
*.pth
*.onnx
mlruns/
wandb/
chroma_db/

# ===== IDE =====
.idea/
.vscode/
*.swp
*.swo
.cursor/

# ===== OS =====
.DS_Store
Thumbs.db

# ===== Logs =====
*.log
logs/
```

---

## 💻 GitHub CLI

### Installation

```bash
# Windows
winget install GitHub.cli

# macOS
brew install gh

# Linux
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh
```

### Authentication

```bash
# Login interactively
gh auth login

# Login with token
gh auth login --with-token < token.txt

# Check auth status
gh auth status
```

### Essential Commands

```bash
# ===== Repository Operations =====
# Create repo
gh repo create my-tool --public --description "Security tool"

# Clone repo
gh repo clone username/repo

# Fork repo
gh repo fork username/repo

# View repo
gh repo view username/repo --web

# ===== Issues =====
# List issues
gh issue list

# Create issue
gh issue create --title "Bug: Detection fails" --body "Description..."

# View issue
gh issue view 42

# Close issue
gh issue close 42

# ===== Pull Requests =====
# Create PR
gh pr create --title "Add new detection" --body "Description..."

# List PRs
gh pr list

# Checkout PR locally
gh pr checkout 123

# Merge PR
gh pr merge 123

# View PR diff
gh pr diff 123

# ===== Actions =====
# List workflows
gh workflow list

# Run workflow
gh workflow run test.yml

# View run logs
gh run view 12345

# ===== Releases =====
# Create release
gh release create v1.0.0 --title "v1.0.0" --notes "Release notes..."

# List releases
gh release list

# Download release assets
gh release download v1.0.0
```

### Useful Aliases

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# GitHub CLI aliases
alias ghpr="gh pr create"
alias ghprl="gh pr list"
alias ghprv="gh pr view --web"
alias ghic="gh issue create"
alias ghil="gh issue list"
alias ghrc="gh repo clone"
alias ghrv="gh repo view --web"
```

---

## 🌿 Branching Strategy

### Git Flow for Security Tools

```
main (stable releases)
  │
  ├── develop (integration branch)
  │     │
  │     ├── feature/add-yara-scanner
  │     ├── feature/llm-detection-agent
  │     └── feature/threat-intel-api
  │
  ├── release/v1.0.0
  │
  └── hotfix/critical-vuln-fix
```

### Branch Naming Conventions

```bash
# Features
feature/add-malware-classifier
feature/implement-sigma-converter

# Bug fixes
fix/false-positive-detection
fix/memory-leak-scanner

# Hotfixes (critical production issues)
hotfix/security-bypass-patch

# Releases
release/v1.0.0
release/v2.1.0

# Experiments
experiment/gpt4-detection
experiment/new-model-architecture
```

### Branch Commands

```bash
# Create and switch to new branch
git checkout -b feature/new-detection

# List branches
git branch -a

# Switch branches
git checkout develop

# Delete local branch
git branch -d feature/completed

# Delete remote branch
git push origin --delete feature/completed

# Sync with remote
git fetch --all --prune
```

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```bash
git commit -m "feat(detection): add ransomware detection module"
git commit -m "fix(parser): handle malformed PE headers"
git commit -m "docs(api): update threat intel API documentation"
git commit -m "refactor(agent): simplify LLM chain logic"
git commit -m "test(scanner): add unit tests for YARA matching"
```

---

## 🔀 Pull Requests & Code Review

### Creating a Pull Request

```bash
# 1. Create feature branch
git checkout -b feature/new-detector

# 2. Make changes and commit
git add .
git commit -m "feat(detector): add cryptominer detection"

# 3. Push branch
git push -u origin feature/new-detector

# 4. Create PR
gh pr create \
  --title "feat(detector): Add cryptominer detection" \
  --body "## Summary
Adds detection capability for cryptocurrency miners.

## Changes
- New YARA rules for miner detection
- CPU usage analysis module
- Mining pool IOC database

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Tested against known samples

## Related Issues
Closes #42" \
  --base develop
```

### PR Template

Create `.github/PULL_REQUEST_TEMPLATE.md`:

```markdown
## Summary
Brief description of changes.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Changes Made
- Change 1
- Change 2

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Input validation added where needed
- [ ] No hardcoded credentials

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manually tested

## Screenshots (if applicable)

## Related Issues
Closes #

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings introduced
```

### Code Review Checklist for Security Tools

```markdown
## Security Code Review Checklist

### Input Validation
- [ ] All user inputs validated
- [ ] File paths sanitized (no path traversal)
- [ ] Command injection prevented
- [ ] SQL injection prevented (if applicable)

### Secrets Management
- [ ] No hardcoded credentials
- [ ] API keys loaded from environment
- [ ] Secrets not logged

### Error Handling
- [ ] Errors don't expose sensitive info
- [ ] Proper exception handling
- [ ] Graceful degradation

### Dependencies
- [ ] No known vulnerable dependencies
- [ ] Dependencies pinned to versions
- [ ] Minimal dependency footprint

### Logging
- [ ] Sensitive data not logged
- [ ] Appropriate log levels
- [ ] Audit trail for security actions

### AI/ML Specific
- [ ] Model inputs sanitized
- [ ] Prompt injection mitigated
- [ ] Rate limiting implemented
- [ ] API costs considered
```

---

## ⚡ GitHub Actions for Security

### Basic CI Workflow

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov

      - name: Run tests
        run: pytest --cov=src tests/

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  lint:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install linters
        run: pip install ruff black mypy

      - name: Run ruff
        run: ruff check .

      - name: Run black
        run: black --check .

      - name: Run mypy
        run: mypy src/
```

### Security Scanning Workflow

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Dependabot
        uses: dependabot/fetch-metadata@v1

      - name: Safety check
        run: |
          pip install safety
          safety check -r requirements.txt

  code-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: python

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: TruffleHog scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}

  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json || true

      - name: Upload Bandit report
        uses: actions/upload-artifact@v3
        with:
          name: bandit-report
          path: bandit-report.json
```

### Detection Rules Testing

Create `.github/workflows/detection-tests.yml`:

```yaml
name: Detection Rules Test

on:
  push:
    paths:
      - 'rules/**'
  pull_request:
    paths:
      - 'rules/**'

jobs:
  test-yara:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install YARA
        run: |
          sudo apt-get update
          sudo apt-get install -y yara

      - name: Validate YARA rules
        run: |
          for rule in rules/yara/*.yar; do
            echo "Validating $rule"
            yara -w "$rule" /dev/null || exit 1
          done

  test-sigma:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install sigma tools
        run: pip install pysigma

      - name: Validate Sigma rules
        run: |
          python -c "
          import yaml
          from pathlib import Path

          for rule_file in Path('rules/sigma').glob('*.yml'):
              print(f'Validating {rule_file}')
              with open(rule_file) as f:
                  rule = yaml.safe_load(f)
                  assert 'title' in rule
                  assert 'detection' in rule
                  assert 'logsource' in rule
          print('All Sigma rules valid!')
          "
```

---

## 🔒 Security Best Practices

### 1. Secrets Management

```bash
# Never commit secrets!
# Use GitHub Secrets for CI/CD

# Add secret via CLI
gh secret set ANTHROPIC_API_KEY

# Use in workflow
# ${{ secrets.ANTHROPIC_API_KEY }}
```

### 2. Branch Protection

Go to **Settings** > **Branches** > **Add rule**:

```yaml
Branch protection for 'main':
  - Require pull request reviews: 1
  - Require status checks:
    - ci / test
    - ci / lint
    - security / code-scan
  - Require signed commits: true
  - Include administrators: true
```

### 3. Dependabot Configuration

Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
    commit-message:
      prefix: "chore(deps)"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "ci"
```

### 4. Security Policy

Create `SECURITY.md`:

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities to: security@example.com

Do NOT create public GitHub issues for security vulnerabilities.

### What to include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline:
- Initial response: 24 hours
- Status update: 72 hours
- Fix timeline: Depends on severity
```

---

## 🤝 Collaboration Workflows

### Fork and PR Workflow

```bash
# 1. Fork the repository (on GitHub or via CLI)
gh repo fork original-owner/repo

# 2. Clone your fork
git clone git@github.com:your-username/repo.git
cd repo

# 3. Add upstream remote
git remote add upstream git@github.com:original-owner/repo.git

# 4. Create feature branch
git checkout -b feature/my-contribution

# 5. Make changes and commit
git add .
git commit -m "feat: add new capability"

# 6. Push to your fork
git push origin feature/my-contribution

# 7. Create PR
gh pr create --repo original-owner/repo

# 8. Keep fork updated
git fetch upstream
git checkout main
git merge upstream/main
git push origin main
```

### Team Workflow

```bash
# Daily workflow
git checkout develop
git pull origin develop
git checkout -b feature/my-task

# Work on feature...
git add .
git commit -m "feat: implement feature"
git push origin feature/my-task

# Create PR to develop
gh pr create --base develop

# After PR merged
git checkout develop
git pull origin develop
git branch -d feature/my-task
```

### Release Workflow

```bash
# 1. Create release branch
git checkout develop
git checkout -b release/v1.0.0

# 2. Update version
echo "1.0.0" > VERSION
git commit -am "chore: bump version to 1.0.0"

# 3. Merge to main
git checkout main
git merge release/v1.0.0

# 4. Tag release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin main --tags

# 5. Create GitHub release
gh release create v1.0.0 \
  --title "v1.0.0" \
  --notes "Release notes..." \
  --target main

# 6. Merge back to develop
git checkout develop
git merge release/v1.0.0
git push origin develop

# 7. Cleanup
git branch -d release/v1.0.0
```

---

**Next**: [Quick Start Guide](./quickstart-guide.md)

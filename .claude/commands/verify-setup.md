# Environment Verification

Verify your AI for the Win environment is correctly configured.

## Usage

```
/verify-setup           # Run full environment check
/verify-setup quick     # Quick check (Python + core packages only)
/verify-setup api       # Check API keys configuration
/verify-setup docker    # Check Docker environment
```

## Instructions

When the user invokes this command:

### 1. Full Verification (no args)

Run the verification script and interpret results:

```bash
python scripts/verify_setup.py
```

Then summarize:
- Python version status
- Core packages (numpy, pandas, sklearn)
- LLM packages (langchain, litellm, instructor)
- Security packages (yara-python, pefile)
- Visualization (plotly, matplotlib)
- API key status
- Docker availability

### 2. Quick Check

Only verify essentials:
```python
import sys
print(f"Python: {sys.version}")

# Core imports
import numpy, pandas, sklearn
print("Core ML packages: OK")
```

### 3. API Key Check

Check for configured API keys:
```python
import os
keys = {
    "ANTHROPIC_API_KEY": "Claude",
    "OPENAI_API_KEY": "OpenAI",
    "GOOGLE_API_KEY": "Gemini",
    "VIRUSTOTAL_API_KEY": "VirusTotal",
    "SHODAN_API_KEY": "Shodan"
}
for key, name in keys.items():
    status = "configured" if os.getenv(key) else "not set"
    print(f"{name}: {status}")
```

### 4. Docker Check

Verify Docker environment:
```bash
docker --version
docker-compose --version
docker ps
```

Check if lab services are available:
- Jupyter notebook
- Elasticsearch
- PostgreSQL

## Expected Output

```
## Environment Verification

### Python
✓ Python 3.11.5 (3.10+ required)

### Core Packages
✓ numpy 1.26.0
✓ pandas 2.1.0
✓ scikit-learn 1.3.0

### LLM Packages
✓ langchain 0.1.0
✓ litellm 1.0.0
! instructor (not installed - optional)

### Security Tools
✓ yara-python 4.3.0
! pefile (not installed - needed for Lab 07)

### API Keys
✓ ANTHROPIC_API_KEY configured
✓ VIRUSTOTAL_API_KEY configured
! OPENAI_API_KEY not set (optional)

### Docker
✓ Docker 24.0.6
✓ Docker Compose 2.21.0

### Summary
Environment ready!
- 12/15 packages installed
- 2/5 API keys configured
- Labs 00-03 ready (no API needed)
- Labs 04+ ready (Claude API configured)
```

## Troubleshooting

If issues found, suggest fixes:

| Issue | Fix |
|-------|-----|
| Python < 3.10 | Install Python 3.10+ from python.org |
| Missing package | `pip install <package>` |
| No API key | Add to `.env` file or environment |
| Docker not running | `docker-compose up -d` |

## Quick Fix Commands

```bash
# Install all dependencies
pip install -r requirements.txt

# Create .env from template
cp .env.example .env

# Start Docker services
docker-compose up -d
```

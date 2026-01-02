# Google Colab Guide

Run all course labs in your browser with zero local setup. Google Colab provides free cloud-based Jupyter notebooks with GPU access.

## Quick Start

### Opening Course Notebooks

**Method 1: Direct Links (Fastest)**

Click any badge to open that lab in Colab:

| Lab | Description | Open in Colab |
|-----|-------------|---------------|
| 00a | Python for Security | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab00a_python_security.ipynb) |
| 00b | ML Concepts | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab00b_ml_concepts.ipynb) |
| 00c | Prompt Engineering | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab00c_prompt_engineering.ipynb) |
| 01 | Phishing Classifier | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb) |
| 02 | Malware Clustering | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab02_malware_clustering.ipynb) |
| 03 | Anomaly Detection | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab03_anomaly_detection.ipynb) |
| 04 | LLM Log Analysis | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab04_llm_log_analysis.ipynb) |
| 05 | Threat Intel Agent | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab05_threat_intel_agent.ipynb) |
| 06 | Security RAG | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab06_security_rag.ipynb) |
| 07 | YARA Generator | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab07_yara_generator.ipynb) |

> 📓 **All 23 notebooks** are available at [`notebooks/`](https://github.com/depalmar/ai_for_the_win/tree/main/notebooks)

**Method 2: From GitHub**

1. Go to [colab.research.google.com](https://colab.research.google.com/)
2. Click **File → Open Notebook → GitHub**
3. Enter repository: `depalmar/ai_for_the_win`
4. Select any notebook from the list

---

## Essential Colab Features

### Installing Packages

Colab has most packages pre-installed, but you may need to install course-specific ones:

```python
# Install packages (run this cell first)
!pip install -q langchain langchain-anthropic chromadb yara-python

# Verify installation
import langchain
print(f"LangChain version: {langchain.__version__}")
```

> 💡 The `!` prefix runs shell commands. The `-q` flag suppresses output.

### Setting Up API Keys (Labs 04+)

**Option 1: Colab Secrets (Recommended)**

1. Click the 🔑 key icon in the left sidebar
2. Add a new secret:
   - Name: `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`, `GOOGLE_API_KEY`)
   - Value: Your API key
3. Toggle "Notebook access" ON
4. Access in code:

```python
from google.colab import userdata

# Get your API key securely
api_key = userdata.get('ANTHROPIC_API_KEY')

# Use with LangChain
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", api_key=api_key)
```

**Option 2: Environment Variable (Quick but less secure)**

```python
import os
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-..."  # Replace with your key

# ⚠️ Don't share notebooks with keys in them!
```

### Using GPU (Free)

For ML-heavy labs (02, 03, 11, 17, 18):

1. Click **Runtime → Change runtime type**
2. Select **T4 GPU** (free tier)
3. Click **Save**

```python
# Verify GPU is available
import torch
print(f"GPU available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")
```

### Mounting Google Drive (Optional)

Save your work permanently:

```python
from google.colab import drive
drive.mount('/content/drive')

# Save files to Drive
import shutil
shutil.copy('my_model.pkl', '/content/drive/MyDrive/ai_for_the_win/')
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Shift + Enter` | Run cell, move to next |
| `Ctrl + Enter` | Run cell, stay in place |
| `Ctrl + M B` | Insert cell below |
| `Ctrl + M A` | Insert cell above |
| `Ctrl + M D` | Delete cell |
| `Ctrl + M M` | Convert to Markdown |
| `Ctrl + M Y` | Convert to Code |
| `Ctrl + /` | Comment/uncomment |
| `Tab` | Code completion |
| `Shift + Tab` | Show function docs |

---

## Colab vs Local Setup

| Feature | Colab | Local |
|---------|-------|-------|
| **Setup time** | 0 minutes | 10-30 minutes |
| **GPU access** | Free T4 GPU | Requires NVIDIA GPU |
| **Session length** | ~12 hrs (resets) | Unlimited |
| **Package control** | Limited | Full control |
| **File persistence** | Temporary (use Drive) | Permanent |
| **Best for** | Learning, experimenting | Production, large projects |

---

## Troubleshooting

### "Session disconnected"

Colab sessions timeout after ~90 minutes of inactivity or ~12 hours total.

**Solution:** Re-run setup cells and reload your data.

```python
# Add this at the top of notebooks to auto-reconnect
from google.colab import output
output.enable_custom_widget_manager()
```

### "Package not found"

```python
# Reinstall required packages
!pip install -q langchain langchain-anthropic langchain-openai chromadb
```

### "Out of memory"

1. Click **Runtime → Restart runtime**
2. Or switch to a GPU runtime (uses GPU memory instead)

### "Cannot import module"

After installing packages, restart the runtime:
1. Click **Runtime → Restart runtime**
2. Re-run your import cells

### API Key Issues

```python
# Debug API key setup
from google.colab import userdata

try:
    key = userdata.get('ANTHROPIC_API_KEY')
    print(f"Key found: {key[:10]}..." if key else "Key is empty")
except Exception as e:
    print(f"Error: {e}")
    print("Make sure you added the secret and enabled notebook access")
```

---

## Lab-Specific Tips

### Labs 01-03 (ML Basics)

No API keys needed! These work out of the box:

```python
# All required packages are pre-installed
import sklearn
import pandas as pd
import numpy as np
```

### Labs 04-07 (LLM Basics)

Set up your API key first:

```python
from google.colab import userdata
import os

# Choose your provider
os.environ["ANTHROPIC_API_KEY"] = userdata.get('ANTHROPIC_API_KEY')
# OR
os.environ["OPENAI_API_KEY"] = userdata.get('OPENAI_API_KEY')
```

### Labs 08-10 (Advanced)

May need additional packages:

```python
!pip install -q langgraph instructor gradio
```

### Labs 11-20 (Expert)

Consider using GPU runtime:

```python
# Check if GPU is available before running heavy models
import torch
assert torch.cuda.is_available(), "Enable GPU: Runtime → Change runtime type → T4 GPU"
```

---

## Saving Your Work

### Download Notebook

**File → Download → Download .ipynb**

### Save to GitHub

1. **File → Save a copy in GitHub**
2. Select your repository
3. Commit changes

### Save to Google Drive

**File → Save a copy in Drive**

---

## Resources

- [Official Colab FAQ](https://research.google.com/colaboratory/faq.html)
- [Colab Pro Features](https://colab.research.google.com/signup) (optional paid tier)
- [Jupyter Basics Guide](./jupyter-basics-guide.md) - Local Jupyter setup
- [API Keys Guide](./api-keys-guide.md) - Getting API keys for Labs 04+

---

## Next Steps

1. **Start with Lab 01** (no API key needed): [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb)

2. **Get an API key** when you reach Lab 04: [API Keys Guide](./api-keys-guide.md)

3. **Join discussions**: [GitHub Discussions](https://github.com/depalmar/ai_for_the_win/discussions)

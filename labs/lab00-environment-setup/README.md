# Lab 00: Environment Setup

**Difficulty**: Beginner | **Prerequisites**: None

Welcome! This guide will get your development environment ready for the AI security labs. Don't worry if you've never set up a coding environment before - we'll walk through everything step by step.

---

## What You'll Set Up

| Tool | What It Does | Why You Need It |
|------|--------------|-----------------|
| **Python 3.10+** | Programming language | All labs use Python |
| **VS Code** or **Cursor** | Code editor | Write and run code |
| **Virtual Environment** | Isolated Python setup | Keep project dependencies clean |
| **Git** | Version control | Clone the repository |
| **Jupyter** | Interactive notebooks | Run lab notebooks |

---

## Step 1: Install Python

### Windows

1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download **Python 3.11** or newer (click the big yellow button)
3. Run the installer
4. **IMPORTANT**: Check the box that says **"Add Python to PATH"**
5. Click "Install Now"

**Verify it worked:**
Open Command Prompt (search "cmd" in Start menu) and type:
```cmd
python --version
```
You should see something like `Python 3.11.5`

### macOS

**Option A: Using Homebrew (recommended)**
```bash
# Install Homebrew first if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11
```

**Option B: Direct Download**
1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download the macOS installer
3. Run the installer

**Verify:**
```bash
python3 --version
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip
```

**Verify:**
```bash
python3 --version
```

---

## Step 2: Install a Code Editor

You need a place to write code. Choose one:

### Option A: VS Code (Free, recommended for beginners)

1. Go to [code.visualstudio.com](https://code.visualstudio.com/)
2. Download and install for your OS
3. Open VS Code
4. Install the **Python extension**:
   - Click the Extensions icon (4 squares) on the left sidebar
   - Search "Python"
   - Click "Install" on the one by Microsoft

### Option B: Cursor (AI-powered, recommended for vibe coding)

1. Go to [cursor.sh](https://cursor.sh/)
2. Download and install
3. It's VS Code with AI built in - same extensions work

### Option C: Other IDEs

Any Python IDE works, but **VS Code or Cursor are recommended** for this course because:
- Better AI assistant integration (Copilot, Claude)
- Lighter weight than full IDEs
- Same tools the labs were built with

> If you already use PyCharm, Sublime, Vim, etc. — that's fine! Just know the walkthroughs assume VS Code.

### AI Coding Assistants (Optional but Recommended)

These tools work alongside your IDE for "vibe coding":

| Tool | Type | Cost | Notes |
|------|------|------|-------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | Terminal | Pay-per-use | Best for multi-file edits, git workflows |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Terminal | Free tier | 1M token context, great for research |
| [Codeium](https://codeium.com/) | IDE extension | Free | Good Copilot alternative |
| [GitHub Copilot](https://github.com/features/copilot) | IDE extension | $10/mo | Inline completions |

> 💡 **Tip:** You don't need all of these. Pick one and learn it well. **Cursor already includes AI** — if you chose Option B, you may not need anything else.

---

## Step 3: Install Git

Git lets you download (clone) the lab repository.

### Windows

1. Go to [git-scm.com/downloads](https://git-scm.com/downloads)
2. Download the Windows installer
3. Run it - accept all defaults

### macOS

Git comes pre-installed. If not:
```bash
xcode-select --install
```

### Linux

```bash
sudo apt install git
```

**Verify:**
```bash
git --version
```

---

## Step 4: Clone the Repository

Now let's download all the labs!

### Windows (Command Prompt or PowerShell)
```cmd
cd %USERPROFILE%\Documents
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win
```

### macOS/Linux
```bash
cd ~/Documents
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win
```

You should now have a folder with all the labs!

---

## Step 5: Create a Virtual Environment

A virtual environment keeps this project's Python packages separate from your system. This prevents conflicts.

### Windows
```cmd
cd ai_for_the_win
python -m venv venv
venv\Scripts\activate
```

You'll see `(venv)` at the start of your command line - that means it's active!

### macOS/Linux
```bash
cd ai_for_the_win
python3 -m venv venv
source venv/bin/activate
```

**Important**: You need to activate the virtual environment every time you open a new terminal to work on the labs.

---

## Step 6: Install Dependencies

With your virtual environment activated, install all required packages:

```bash
pip install -r requirements.txt
```

This might take a few minutes - it's downloading ML libraries, LangChain, and other tools.

**Common Issues:**

| Error | Solution |
|-------|----------|
| `pip not found` | Try `pip3` instead of `pip` |
| Permission denied | Make sure venv is activated |
| Build errors | Install build tools (see Troubleshooting below) |

---

## Step 7: Verify Your Setup

Run the verification script:

```bash
python scripts/verify_setup.py
```

You should see green checkmarks for:
- [x] Python version
- [x] Required packages
- [x] Data files accessible

---

## Step 8: Install Jupyter (for notebooks)

Many labs have interactive notebooks. Install Jupyter:

```bash
pip install jupyter
```

To run a notebook:
```bash
jupyter notebook
```

This opens a browser window. Navigate to `notebooks/` and click any `.ipynb` file.

**VS Code Alternative**: Install the "Jupyter" extension in VS Code to run notebooks directly in your editor.

---

## Step 9: Test Run a Lab

Let's make sure everything works by running Lab 01:

```bash
cd labs/lab01-phishing-classifier
python solution/main.py
```

You should see output about phishing email classification. If you do - you're ready!

---

## Quick Reference: Daily Workflow

Every time you work on the labs:

```bash
# 1. Open terminal and navigate to project
cd ~/Documents/ai_for_the_win   # or wherever you cloned it

# 2. Activate virtual environment
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# 3. Work on labs!
cd labs/lab01-phishing-classifier
python solution/main.py

# 4. Or run notebooks
jupyter notebook
```

---

## Troubleshooting

### "Python not found" or "python is not recognized"

**Windows**: Python wasn't added to PATH during install
- Reinstall Python and CHECK the "Add to PATH" box
- Or manually add: `C:\Users\<YourName>\AppData\Local\Programs\Python\Python311` to PATH

**macOS/Linux**: Try `python3` instead of `python`

### "No module named pip"

```bash
python -m ensurepip --upgrade
```

### Build errors during pip install

**Windows**: Install Visual Studio Build Tools
- Download from [visualstudio.microsoft.com/visual-cpp-build-tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- Select "Desktop development with C++"

**macOS**:
```bash
xcode-select --install
```

**Linux**:
```bash
sudo apt install build-essential python3-dev
```

### "Permission denied" errors

Never use `sudo pip install` - it can break your system Python. Make sure your virtual environment is activated (you should see `(venv)` in your prompt).

### Jupyter won't start

```bash
pip install --upgrade jupyter
jupyter notebook --no-browser
# Then manually open the URL it prints
```

### SSL Certificate errors

```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

---

## What's Next?

Once your environment is set up:

| Your Background | Next Lab |
|-----------------|----------|
| New to Python | [Lab 00a: Python Basics](../lab00a-python-security-fundamentals/) |
| Know Python, new to ML | [Lab 00b: ML Concepts](../lab00b-ml-concepts-primer/) |
| Know ML, new to LLMs | [Lab 00c: Prompt Engineering](../lab00c-intro-prompt-engineering/) |
| Ready to build! | [Lab 01: Phishing Classifier](../lab01-phishing-classifier/) |

---

## Getting Help

Stuck? Here's where to get help:

1. **Check the troubleshooting section above**
2. **Search the error message** - chances are someone else had the same issue
3. **Open a GitHub issue**: [github.com/depalmar/ai_for_the_win/issues](https://github.com/depalmar/ai_for_the_win/issues)
4. **Ask an AI**: Paste the error into ChatGPT or Claude - they're great at debugging setup issues!

---

**You're all set!** Head to [Lab 00a](../lab00a-python-security-fundamentals/) if you're new to Python, or [Lab 01](../lab01-phishing-classifier/) if you're ready to build your first security ML tool.

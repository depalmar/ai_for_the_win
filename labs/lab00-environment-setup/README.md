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

## Terminal Basics for Beginners

If you've never used a terminal (command line) before, read this section first. If you're comfortable with `cd`, `ls`, and running commands, skip to [Step 1: Install Python](#step-1-install-python).

### What is a Terminal?

A **terminal** (also called command line, command prompt, or shell) is a text-based way to interact with your computer. Instead of clicking on folders and files, you type commands.

- **Windows**: Called "Command Prompt" or "PowerShell" (search in Start menu)
- **macOS**: Called "Terminal" (search with Spotlight or find in Applications → Utilities)
- **Linux**: Called "Terminal" (usually in your applications menu)

### Opening a Terminal

| Operating System | How to Open |
|------------------|-------------|
| **Windows** | Press `Win + R`, type `cmd`, press Enter. Or search "Command Prompt" in Start menu |
| **macOS** | Press `Cmd + Space`, type "Terminal", press Enter |
| **Linux** | Press `Ctrl + Alt + T` or find Terminal in applications |

### Essential Commands

These commands work in all terminals. Learn these and you can navigate anywhere!

| Windows Command | macOS/Linux Command | What It Does | Example |
|-----------------|---------------------|--------------|---------|
| `cd folder` | `cd folder` | **C**hange **D**irectory - go into a folder | `cd Documents` |
| `cd ..` | `cd ..` | Go up one folder level | `cd ..` |
| `cd` or `cd %USERPROFILE%` | `cd ~` | Go to your home folder | `cd ~` |
| `dir` | `ls` | **L**i**s**t files in current folder | `ls` |
| `cls` | `clear` | Clear the screen | `clear` |
| `type file.txt` | `cat file.txt` | Show contents of a file | `cat README.md` |
| `mkdir folder` | `mkdir folder` | **M**a**k**e a new **dir**ectory (folder) | `mkdir projects` |
| `python script.py` | `python3 script.py` | Run a Python script | `python3 main.py` |

### Understanding File Paths

A **path** is the address of a file or folder on your computer.

```
Absolute path (full address from root):
  Windows:  C:\Users\John\Documents\ai_for_the_win\labs
  macOS:    /Users/John/Documents/ai_for_the_win/labs

Relative path (from where you currently are):
  ./labs          → labs folder in current directory
  ../             → parent folder (one level up)
  ../other_folder → sibling folder
```

**The `.` means "current folder" and `..` means "parent folder"**

### Practice Exercise: Navigate Your Computer

Try this exercise to get comfortable with the terminal:

```bash
# 1. Open your terminal

# 2. See where you are (print working directory)
pwd                    # macOS/Linux
cd                     # Windows (shows current path)

# 3. Go to your Documents folder
cd Documents           # If Documents is in your current folder
# OR use the full path:
cd ~/Documents         # macOS/Linux
cd %USERPROFILE%\Documents  # Windows

# 4. List what's in Documents
ls                     # macOS/Linux
dir                    # Windows

# 5. Create a test folder
mkdir test_folder

# 6. Go into it
cd test_folder

# 7. Go back up
cd ..

# 8. Delete the test folder (be careful with delete commands!)
rmdir test_folder      # Works on all systems (only if folder is empty)
```

### Common Mistakes and Fixes

| Problem | Cause | Solution |
|---------|-------|----------|
| "command not found" | Typo or program not installed | Check spelling; install the program |
| "No such file or directory" | Path doesn't exist | Use `ls`/`dir` to see what's actually there |
| "Permission denied" | Need admin rights OR wrong folder | Try different folder; don't use `sudo` unless needed |
| Command does nothing | Waiting for more input | Press `Ctrl + C` to cancel |

### Tips for Success

1. **Tab completion**: Start typing a folder name and press `Tab` - the terminal will auto-complete it
2. **Up arrow**: Press `↑` to recall previous commands
3. **Copy/paste**: 
   - Windows: Right-click to paste in Command Prompt
   - macOS: `Cmd + V` works in Terminal
   - Linux: `Ctrl + Shift + V` (note the Shift!)
4. **Cancel a command**: Press `Ctrl + C` to stop a running command

### Git Basics for Beginners

**What is Git?** Git is a version control system - it tracks changes to files over time. Think of it as "save points" for code. GitHub is a website that hosts Git repositories (projects) so people can share code.

**Why do we use it?** You'll use `git clone` to download this course's labs to your computer.

#### Key Concepts

```
Repository (repo)  = A project folder tracked by Git
Clone              = Download a copy of a repo to your computer
Commit             = Save a snapshot of changes
Push               = Upload your commits to GitHub
Pull               = Download latest changes from GitHub
```

#### Commands You'll Use

| Command | What It Does | When You Use It |
|---------|--------------|-----------------|
| `git clone <url>` | Download a repository | Once, at the start |
| `git status` | See what files have changed | To check your work |
| `git pull` | Get latest updates | If course is updated |
| `git add <file>` | Stage changes for commit | Before saving changes |
| `git commit -m "message"` | Save a snapshot | After making changes |

#### Your First Git Commands (Preview)

```bash
# Download the course (you'll do this in Step 4)
git clone https://github.com/depalmar/ai_for_the_win.git

# Check status (see what's changed)
git status

# Get updates if the course is updated later
git pull
```

> 💡 **Don't worry about Git yet** - we'll walk through the exact commands in Step 4. Just know that `git clone` is like "download" and `git pull` is like "update".

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

### What is a Virtual Environment (and Why You Need One)?

A **virtual environment** is an isolated Python installation with its own packages. Think of it as a bubble where this course's dependencies live without affecting your other Python projects.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WHY VIRTUAL ENVIRONMENTS?                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   WITHOUT VIRTUAL ENVIRONMENT:                                              │
│   ────────────────────────────                                              │
│   System Python ← ALL projects share packages                               │
│        │                                                                    │
│        ├── Project A needs pandas 1.5                                      │
│        ├── Project B needs pandas 2.0  ← CONFLICT!                         │
│        └── Project C needs pandas 1.3  ← BROKEN!                           │
│                                                                             │
│   WITH VIRTUAL ENVIRONMENTS:                                                │
│   ─────────────────────────────                                            │
│   System Python                                                             │
│        │                                                                    │
│        ├── venv_projectA/ → pandas 1.5 ✓                                   │
│        ├── venv_projectB/ → pandas 2.0 ✓                                   │
│        └── venv_projectC/ → pandas 1.3 ✓                                   │
│                                                                             │
│   Each project gets exactly what it needs!                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Real-world example**: This course uses LangChain 0.3.x. Another project might need LangChain 0.1.x (the API changed significantly). Without virtual environments, you'd have to uninstall and reinstall every time you switch projects!

### How Virtual Environments Work

```
When you activate a virtual environment:

1. PATH is modified to point to venv's Python first
   Before: python → /usr/bin/python (system)
   After:  python → ./venv/bin/python (project-specific)

2. Packages install into venv folder
   pip install pandas → venv/lib/python3.11/site-packages/pandas/

3. Your system Python is untouched
   Other projects still work as before
```

### Creating Your Virtual Environment

#### Windows
```cmd
cd ai_for_the_win
python -m venv venv
venv\Scripts\activate
```

You'll see `(venv)` at the start of your command line - that means it's active!

#### macOS/Linux
```bash
cd ai_for_the_win
python3 -m venv venv
source venv/bin/activate
```

### Understanding the `venv` Folder

After creation, you'll have a `venv` folder:

```
venv/
├── bin/ (or Scripts/ on Windows)
│   ├── activate         ← The activation script
│   ├── python          ← Python interpreter
│   └── pip             ← Package installer
├── lib/
│   └── python3.11/
│       └── site-packages/  ← Installed packages go here
└── pyvenv.cfg          ← Configuration file
```

> ⚠️ **Never commit `venv/` to git!** It's in `.gitignore` for a reason - each person should create their own from `requirements.txt`.

### Daily Workflow: Activating Your Environment

**Important**: You need to activate the virtual environment every time you open a new terminal:

```bash
# Navigate to project
cd ai_for_the_win

# Activate (choose your OS)
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# Now you're ready to work!
# (venv) shows in your prompt
```

### Common Questions

**Q: How do I know if my venv is active?**
A: Look for `(venv)` at the start of your command prompt.

**Q: How do I deactivate?**
A: Just type `deactivate` and press Enter.

**Q: Can I delete and recreate the venv?**
A: Yes! Delete the `venv` folder, then recreate it:
```bash
rm -rf venv                    # Delete
python3 -m venv venv           # Recreate
source venv/bin/activate       # Activate
pip install -r requirements.txt # Reinstall packages
```

**Q: Why not use conda?**
A: Conda works too! But `venv` is built into Python and simpler for this course. If you prefer conda, create an environment and install from `requirements.txt`.

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

## Using AI to Accelerate Your Learning

AI assistants are incredibly powerful learning tools. Here's how to use them effectively throughout this course.

### AI Tools for Learning

| Tool | Best For | Cost |
|------|----------|------|
| **[Claude.ai](https://claude.ai)** | Explaining concepts, debugging, code review | Free tier available |
| **[ChatGPT](https://chat.openai.com)** | General help, explaining errors | Free tier available |
| **[Perplexity](https://perplexity.ai)** | Research, finding resources | Free |
| **[Cursor](https://cursor.sh)** | Coding with AI assistance built-in | Free tier, $20/mo pro |
| **[GitHub Copilot](https://github.com/features/copilot)** | Code completion in your editor | $10/mo |

### How to Ask AI for Help (Effective Prompts)

#### When You Get an Error

```
I'm getting this error when running my Python code:

[Paste the FULL error traceback here]

My code is:
[Paste the relevant code]

I'm trying to [explain what you're trying to do].

What's wrong and how do I fix it?
```

#### When You Don't Understand a Concept

```
I'm learning about [concept] in cybersecurity/ML.

Explain [concept] like I'm a beginner. Include:
1. What it is in simple terms
2. Why it matters for security
3. A simple example
4. How it's used in real security tools
```

#### When You're Stuck on a Lab

```
I'm working on [Lab name/number] and I'm stuck on [specific task].

Here's what I've tried:
[Your attempt]

Here's the error/problem I'm seeing:
[What's happening]

The expected outcome is:
[What should happen]

Can you help me understand what I'm missing?
```

### Learning Strategies with AI

#### 1. Explain Code to You

```python
# Don't understand this code? Ask AI:
"Explain this code line by line:

df['risk_score'] = df.apply(lambda x: calculate_risk(x['events'], x['user']), axis=1)

What does each part do? I'm new to pandas."
```

#### 2. Rubber Duck Debugging with AI

When stuck, explain your problem to AI:
- What you're trying to do
- What you've tried
- What you expected vs. what happened

Often, just explaining the problem helps you solve it!

#### 3. Ask for Alternative Approaches

```
"I solved this problem using [your approach].
Are there better/simpler ways to do this?
What would a more experienced developer do?"
```

#### 4. Request Practice Problems

```
"I just learned about [concept] in Lab [X].
Give me 3 practice problems to reinforce this concept,
starting easy and getting harder."
```

#### 5. Ask AI to Review Your Code

```
"Review this code for:
1. Bugs or errors
2. Security issues
3. Ways to make it cleaner
4. Best practices I'm missing

[Your code here]"
```

### AI Coding Assistants in Your Editor

If you're using **Cursor** (recommended) or **VS Code with Copilot**:

| Action | How | When to Use |
|--------|-----|-------------|
| **Autocomplete** | Just type, suggestions appear | Writing boilerplate code |
| **Chat** | `Ctrl+L` (Cursor) | Ask questions about your code |
| **Explain** | Select code → "Explain this" | Understanding unfamiliar code |
| **Fix** | Select error → "Fix this" | Debugging |
| **Generate** | Describe what you want in comments | Creating new functions |

#### Example: Generate Code from Comments

```python
# In Cursor/Copilot, write a comment describing what you want:

# Function that extracts all IP addresses from a log file
# and returns them as a list, excluding private IPs

# Then press Tab or Enter - AI will generate the function!
```

### Best Practices for Learning with AI

#### ✅ DO

- **Understand before moving on** - Don't just copy AI code; make sure you understand it
- **Verify AI answers** - AI can be wrong; test the code it gives you
- **Ask follow-up questions** - "Why does this work?" "What if I changed X?"
- **Use AI to fill knowledge gaps** - "I don't understand regex. Explain the basics."
- **Learn from AI explanations** - Read them carefully, don't just scan for code

#### ❌ DON'T

- **Don't blindly copy-paste** - Understand what the code does first
- **Don't skip the learning** - If AI solves it instantly, still understand the solution
- **Don't assume AI is always right** - It makes mistakes, especially with newer libraries
- **Don't ask AI to do entire labs** - You'll miss the learning; use it for help, not completion
- **Don't forget to experiment** - After AI helps, try modifying the code yourself

### Example: Using AI Throughout a Lab

```
1. START LAB
   Read the objectives, try it yourself first

2. GET STUCK
   "I'm trying to [X] but getting [error]. What am I missing?"

3. UNDERSTAND THE FIX
   "Why does your solution work? What was wrong with my approach?"

4. COMPLETE THE LAB
   Implement the fix, verify it works

5. REINFORCE LEARNING
   "Give me a similar problem to practice this concept"

6. GO DEEPER (optional)
   "What are advanced techniques for [this concept]?"
```

### Quick AI Help Templates

Save these for quick copy-paste:

**Error Help:**
```
Error: [paste error]
Code: [paste code]
Goal: [what you're trying to do]
Help me fix this.
```

**Concept Explanation:**
```
Explain [concept] for someone learning cybersecurity.
Include a simple example and why it matters.
```

**Code Review:**
```
Review this code for bugs, security issues, and improvements:
[paste code]
```

**Learning Reinforcement:**
```
I just learned [concept]. Give me 3 practice exercises
to reinforce this, with solutions I can check.
```

> 💡 **Pro Tip**: The best way to learn is to **try first, then ask for help**. AI is a tutor, not a replacement for thinking through problems yourself.

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

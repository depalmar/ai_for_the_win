# Jupyter Notebooks: A Quick Guide for Security Analysts

**Prerequisites**: Python installed, virtual environment set up

If you've never used Jupyter notebooks before, this guide will get you up to speed. Notebooks are interactive documents that let you run code, see results, and add notes - perfect for experimenting with ML models.

---

## What is a Jupyter Notebook?

A notebook is a document (`.ipynb` file) with **cells** that can contain:
- **Code** - Python that you can run
- **Markdown** - Formatted text, notes, explanations
- **Output** - Results, charts, tables

Think of it like a lab notebook where you can run experiments and document findings in one place.

---

## Installing Jupyter

With your virtual environment activated:

```bash
pip install jupyter
```

Or for a more feature-rich experience:
```bash
pip install jupyterlab
```

---

## Starting Jupyter

### Option 1: Classic Notebook Interface
```bash
jupyter notebook
```

This opens a browser tab with a file explorer. Navigate to `notebooks/` and click any `.ipynb` file.

### Option 2: JupyterLab (Modern Interface)
```bash
jupyter lab
```

Same idea, but with a more modern IDE-like interface.

### Option 3: VS Code (Recommended)
1. Install the "Jupyter" extension in VS Code
2. Open any `.ipynb` file
3. Run cells directly in VS Code

---

## Understanding the Interface

When you open a notebook, you'll see:

```
┌─────────────────────────────────────────────────────────────┐
│  [▶ Run] [⬛ Stop] [↻ Restart]  [+ Cell]                    │  <- Toolbar
├─────────────────────────────────────────────────────────────┤
│  [1]: import pandas as pd                                   │  <- Code Cell
│       from sklearn.ensemble import RandomForestClassifier   │
├─────────────────────────────────────────────────────────────┤
│  ## Training the Model                                      │  <- Markdown Cell
│  We'll use a Random Forest classifier for this task.        │
├─────────────────────────────────────────────────────────────┤
│  [2]: model = RandomForestClassifier()                      │  <- Code Cell
│       model.fit(X_train, y_train)                           │
│                                                             │
│  Out[2]: RandomForestClassifier()                           │  <- Output
└─────────────────────────────────────────────────────────────┘
```

---

## Running Cells

### Keyboard Shortcuts (Memorize These!)

| Shortcut | Action |
|----------|--------|
| `Shift + Enter` | Run cell, move to next |
| `Ctrl + Enter` | Run cell, stay in place |
| `Esc` | Exit edit mode (command mode) |
| `Enter` | Enter edit mode |
| `A` | Insert cell above (command mode) |
| `B` | Insert cell below (command mode) |
| `DD` | Delete cell (command mode, press D twice) |
| `M` | Change cell to Markdown (command mode) |
| `Y` | Change cell to Code (command mode) |

### Running All Cells

Menu: **Kernel → Restart & Run All**

Or in command mode: Press `0` twice to restart kernel, then `Shift + Enter` through cells.

---

## Cell Execution Order Matters

Cells can be run in any order, but the **execution order affects your results**.

```python
# Cell 1 - Run first
x = 10

# Cell 2 - Run second
y = x + 5
print(y)  # 15

# Cell 3 - What if you run this before Cell 1?
z = x * 2  # NameError: 'x' is not defined
```

**Pro Tip**: If things get weird, restart the kernel and run all cells from the top.

---

## Working with Lab Notebooks

Each lab has a notebook in the `notebooks/` folder. Here's how to use them:

### Step 1: Open the Notebook
```bash
cd ai_for_the_win
jupyter notebook notebooks/lab01_phishing_classifier.ipynb
```

### Step 2: Read the Introduction
The first cells usually explain what you'll build.

### Step 3: Run Cells Sequentially
Work through the notebook top to bottom using `Shift + Enter`.

### Step 4: Experiment!
Modify code, rerun cells, see what happens.

### Step 5: Complete the Exercises
Look for cells with `# TODO` or `# YOUR CODE HERE` comments.

---

## Common Operations

### Viewing DataFrames
```python
import pandas as pd

df = pd.read_csv("data/logs.csv")
df.head()  # Shows first 5 rows in a nice table
```

### Displaying Plots
```python
import matplotlib.pyplot as plt

plt.figure(figsize=(10, 6))
plt.plot(data)
plt.title("My Chart")
plt.show()  # Displays inline in the notebook
```

### Checking Variable Values
```python
# Just type the variable name
my_list = [1, 2, 3]
my_list  # Displays the value

# Or use print for more control
print(f"Length: {len(my_list)}")
```

---

## Saving and Checkpoints

Notebooks auto-save, but you can manually save:
- `Ctrl + S` (or `Cmd + S` on Mac)
- Menu: **File → Save**

Jupyter also creates checkpoints. To revert:
- Menu: **File → Revert to Checkpoint**

---

## Clearing Outputs

Before sharing or committing notebooks:

**Clear all outputs:**
Menu: **Kernel → Restart & Clear Output**

This removes all cell outputs while keeping your code.

---

## Troubleshooting

### Kernel Dies or Gets Stuck

1. **Interrupt**: Menu → Kernel → Interrupt (or press `II`)
2. **Restart**: Menu → Kernel → Restart
3. **Hard restart**: Close browser, stop Jupyter in terminal (`Ctrl + C`), restart

### "ModuleNotFoundError"

The notebook might be using a different Python than your virtual environment:

```bash
# Make sure venv is activated, then reinstall the kernel
pip install ipykernel
python -m ipykernel install --user --name=ai-security-labs
```

Then select "ai-security-labs" as your kernel in the notebook.

### Notebook Won't Open

```bash
# Try with a specific browser
jupyter notebook --browser=chrome

# Or copy the URL with token manually
jupyter notebook --no-browser
# Copy the localhost URL and paste in browser
```

### Large Outputs Slow Things Down

For large data:
```python
# Instead of displaying entire DataFrame
df  # Don't do this with 1M rows

# Use head/tail
df.head(10)

# Or shape
print(f"Shape: {df.shape}")
```

---

## Google Colab Alternative

Don't want to install anything? Use Google Colab:

1. Go to [colab.research.google.com](https://colab.research.google.com/)
2. File → Open Notebook → GitHub
3. Enter: `depalmar/ai_for_the_win`
4. Select a notebook

Colab runs in the cloud - free GPU included!

---

## Quick Reference Card

```
╔═══════════════════════════════════════════════════════════╗
║  JUPYTER NOTEBOOK CHEAT SHEET                             ║
╠═══════════════════════════════════════════════════════════╣
║  RUNNING CELLS                                            ║
║  Shift + Enter    Run and move to next cell               ║
║  Ctrl + Enter     Run and stay in cell                    ║
║                                                           ║
║  NAVIGATION (Command Mode - press Esc first)              ║
║  A               Insert cell above                        ║
║  B               Insert cell below                        ║
║  DD              Delete cell                              ║
║  M               Convert to Markdown                      ║
║  Y               Convert to Code                          ║
║  Up/Down         Navigate cells                           ║
║                                                           ║
║  EDITING                                                  ║
║  Enter           Edit cell                                ║
║  Tab             Code completion                          ║
║  Shift + Tab     Show function docs                       ║
║                                                           ║
║  KERNEL                                                   ║
║  00              Restart kernel (press 0 twice)           ║
║  II              Interrupt execution                      ║
╚═══════════════════════════════════════════════════════════╝
```

---

## Next Steps

Now that you know Jupyter basics:
- Open `notebooks/lab01_phishing_classifier.ipynb` and work through it
- Experiment by modifying code and rerunning cells
- Try the exercises at the end of each notebook

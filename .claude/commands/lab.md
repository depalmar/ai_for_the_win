# Lab Navigator

Navigate, explore, and run labs in the AI for the Win training program.

## Usage

```
/lab                    # List all labs with status
/lab <number>           # Show lab details (e.g., /Lab 36)
/lab <number> start     # Open lab starter code
/lab <number> solution  # Show solution
/lab <number> test      # Run lab tests
```

## Instructions

When the user invokes this command:

1. **Parse the argument** to determine action:
   - No argument: List all labs with brief descriptions
   - Number only (e.g., "05", "10b"): Show lab details
   - Number + "start": Open starter code in editor
   - Number + "solution": Show solution code
   - Number + "test": Run pytest for that lab

2. **Lab Discovery**:
   - Labs are in `labs/` directory
   - Format: `labXX-topic-name/` or `labXXa-topic-name/`
   - Each has: README.md, starter/, solution/, data/

3. **Lab Listing** (no args):
   ```
   ## Intro Labs (01-09)
   - lab10: Python Security Fundamentals
   - lab35: ML Concepts Primer
   ...

   ## ML Foundations (01-03)
   - lab10: Phishing Classifier
   ...

   ## LLM Basics (04-07)
   ...
   ```

4. **Lab Details** (with number):
   - Read and summarize the lab's README.md
   - Show objectives, prerequisites, estimated time
   - List files in starter/ and solution/
   - Show test file location

5. **Start Lab**:
   - Open `labs/labXX-*/starter/main.py` in VS Code
   - Show first few TODOs from the file

6. **Show Solution**:
   - Display key parts of `labs/labXX-*/solution/main.py`
   - Explain the approach taken

7. **Run Tests**:
   - Execute: `pytest tests/test_labXX_*.py -v`
   - Report pass/fail status

## Lab Categories

| Range | Category | API Required |
|-------|----------|--------------|
| 01-09 | Intro/Fundamentals | No |
| 01-03 | ML Foundations | No |
| 04-07 | LLM Basics | Yes |
| 08-10 | Advanced Agents | Yes |
| 11-20 | Expert DFIR | Yes |

## Example Output

```
## Lab 36: Threat Intelligence Agent

**Objectives:**
- Build an agent that queries threat intel APIs
- Implement tool calling for IOC enrichment
- Create structured threat reports

**Prerequisites:** Lab 35 (LLM basics), API key configured

**Files:**
- Starter: labs/lab16-threat-intel-agent/starter/main.py
- Solution: labs/lab16-threat-intel-agent/solution/main.py
- Tests: tests/test_lab36_threat_intel.py

**Run:** pytest tests/test_lab36_threat_intel.py -v
```

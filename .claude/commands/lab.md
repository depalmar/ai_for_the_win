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
   ## Foundation & Setup (00-09)
   - lab00: Environment Setup
   - lab01: Python Security Fundamentals
   - lab02: Prompt Engineering
   - lab03: Vibe Coding with AI
   - lab04: ML Concepts Primer
   - lab05: AI in Security Operations
   - lab06: Visualization & Stats
   - lab07: Hello World ML
   - lab08: Working with APIs
   - lab09: CTF Fundamentals

   ## ML Foundations (10-13)
   - lab10: Phishing Classifier
   - lab11: Malware Clustering
   - lab12: Anomaly Detection
   - lab13: ML vs LLM

   ## LLM Basics & Detection (14-21)
   - lab14: First AI Agent
   - lab15: LLM Log Analysis
   - lab16: Threat Intel Agent
   - lab17: Embeddings & Vectors
   - lab18: Security RAG
   - lab19: Binary Basics
   - lab20: Sigma Fundamentals
   - lab21: YARA Generator

   ## Advanced Pipelines (22-29)
   - lab22: Vuln Scanner AI
   - lab23: Detection Pipeline
   - lab24: Monitoring AI Systems
   - lab25: DFIR Fundamentals
   - lab26: Windows Event Log Analysis
   - lab27: Windows Registry Forensics
   - lab28: Live Response
   - lab29: IR Copilot

   ## Expert DFIR, Cloud, Red Team (30-50)
   - lab30-50: Advanced topics including ransomware, memory forensics,
     C2 analysis, adversarial ML, cloud security, and LLM red teaming
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
| 00-09 | Foundation & Setup | No |
| 10-13 | ML Foundations | No |
| 14-21 | LLM Basics & Detection | Yes |
| 22-29 | Advanced Pipelines | Yes |
| 30-50 | Expert DFIR, Cloud, Red Team | Yes |

## Example Output

```
## Lab 16: Threat Intelligence Agent

**Objectives:**
- Build an agent that queries threat intel APIs
- Implement tool calling for IOC enrichment
- Create structured threat reports

**Prerequisites:** Lab 15 (LLM Log Analysis), API key configured

**Files:**
- Starter: labs/lab16-threat-intel-agent/starter/main.py
- Solution: labs/lab16-threat-intel-agent/solution/main.py
- Tests: tests/test_lab16_threat_intel.py

**Run:** pytest tests/test_lab16_threat_intel.py -v
```

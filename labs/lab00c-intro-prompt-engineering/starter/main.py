#!/usr/bin/env python3
"""
Lab 00c: Introduction to Prompt Engineering - Exercises

This lab teaches prompt engineering for security tasks.
You can use these prompts in two ways:

1. PLAYGROUND MODE (No API Key):
   - Copy the generated prompts
   - Paste into Google AI Studio, Claude.ai, or ChatGPT

2. API MODE (Requires API Key):
   - Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY
   - The script will call the API directly

Run: python main.py
"""

import json
import os
from pathlib import Path

# Check for API availability
HAS_ANTHROPIC = bool(os.environ.get("ANTHROPIC_API_KEY"))
HAS_OPENAI = bool(os.environ.get("OPENAI_API_KEY"))
HAS_API = HAS_ANTHROPIC or HAS_OPENAI


def load_samples() -> dict:
    """Load security samples for exercises."""
    data_path = Path(__file__).parent.parent / "data" / "security_samples.json"
    with open(data_path) as f:
        return json.load(f)


def print_prompt(prompt: str, title: str = "PROMPT"):
    """Display a prompt in a formatted box."""
    print(f"\n{'='*60}")
    print(f"📝 {title}")
    print("=" * 60)
    print(prompt)
    print("=" * 60)


def call_llm(prompt: str) -> str | None:
    """Call LLM API if available, otherwise return None."""
    if not HAS_API:
        return None

    try:
        if HAS_ANTHROPIC:
            from anthropic import Anthropic

            client = Anthropic()
            response = client.messages.create(
                model="claude-haiku-4-5",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text
        elif HAS_OPENAI:
            from openai import OpenAI

            client = OpenAI()
            response = client.chat.completions.create(
                model="gpt-5-mini", messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
    except Exception as e:
        print(f"API Error: {e}")
        return None


# =============================================================================
# EXERCISE 1: Basic vs Structured Prompts
# =============================================================================


def exercise_1_weak_prompt(log_entries: list[str]) -> str:
    """
    WEAK PROMPT - Missing context, structure, and specifics.

    TODO: Look at this prompt and identify what's missing.
    """
    return f"analyze these logs: {log_entries}"


def exercise_1_better_prompt(log_entries: list[str]) -> str:
    """
    TODO: Improve this prompt by adding:
    1. Role/context for the LLM
    2. Clear task description
    3. Specific output format
    4. The actual data to analyze

    Hint: Use the template structure from the README.
    """
    # TODO: Rewrite this prompt
    prompt = f"""
Analyze these log entries:

{chr(10).join(log_entries)}

Tell me what you find.
"""
    return prompt


def run_exercise_1():
    """Compare weak vs structured prompts."""
    print("\n" + "=" * 60)
    print("EXERCISE 1: Basic vs Structured Prompts")
    print("=" * 60)

    samples = load_samples()
    logs = samples["log_entries"]

    # Show weak prompt
    weak = exercise_1_weak_prompt(logs)
    print_prompt(weak, "WEAK PROMPT (Don't use this!)")
    print("\n❌ Problems: No context, no format, unclear task")

    # Show improved prompt
    better = exercise_1_better_prompt(logs)
    print_prompt(better, "YOUR IMPROVED PROMPT")

    print("\n📋 Copy this prompt and paste it into:")
    print("   - Google AI Studio: aistudio.google.com")
    print("   - Claude: claude.ai")
    print("   - ChatGPT: chat.openai.com")

    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(better)
        if response:
            print(response)


# =============================================================================
# EXERCISE 2: IOC Extraction
# =============================================================================


def exercise_2_ioc_extraction(threat_report: str) -> str:
    """
    TODO: Write a prompt to extract IOCs from a threat report.

    IOCs to extract:
    - IP addresses
    - Domains
    - File paths
    - Registry keys
    - Hashes (MD5, SHA1, SHA256)

    Output should be structured (JSON or markdown table).
    """
    # TODO: Write your prompt here
    prompt = f"""
Extract IOCs from this threat report.

REPORT:
{threat_report}

# TODO: Add instructions for:
# - What types of IOCs to look for
# - How to format the output
# - What to do if uncertain
"""
    return prompt


def run_exercise_2():
    """Practice IOC extraction prompts."""
    print("\n" + "=" * 60)
    print("EXERCISE 2: IOC Extraction Prompt")
    print("=" * 60)

    samples = load_samples()
    report = samples["threat_report_excerpt"]

    print("\nThreat Report Excerpt:")
    print("-" * 40)
    print(report[:200] + "...")

    prompt = exercise_2_ioc_extraction(report)
    print_prompt(prompt, "YOUR IOC EXTRACTION PROMPT")

    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# EXERCISE 3: Phishing Analysis
# =============================================================================


def exercise_3_phishing_analysis(email: dict) -> str:
    """
    TODO: Write a prompt to analyze a suspicious email.

    The analysis should cover:
    - Is it likely phishing? (confidence level)
    - What red flags are present?
    - What legitimate elements exist (if any)?
    - Recommended action
    """
    # TODO: Write your prompt here
    prompt = f"""
Analyze this email for phishing indicators.

FROM: {email['from']}
TO: {email['to']}
SUBJECT: {email['subject']}

BODY:
{email['body']}

# TODO: Add specific analysis instructions
"""
    return prompt


def run_exercise_3():
    """Practice phishing analysis prompts."""
    print("\n" + "=" * 60)
    print("EXERCISE 3: Phishing Analysis Prompt")
    print("=" * 60)

    samples = load_samples()
    email = samples["suspicious_email"]

    print("\nSuspicious Email:")
    print("-" * 40)
    print(f"From: {email['from']}")
    print(f"Subject: {email['subject']}")

    prompt = exercise_3_phishing_analysis(email)
    print_prompt(prompt, "YOUR PHISHING ANALYSIS PROMPT")

    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# EXERCISE 4: PowerShell Deobfuscation
# =============================================================================


def exercise_4_powershell_analysis(encoded_command: str) -> str:
    """
    TODO: Write a prompt to analyze suspicious PowerShell.

    The prompt should ask the LLM to:
    - Decode any encoding (base64, etc.)
    - Explain what the command does
    - Identify malicious behaviors
    - Extract IOCs
    """
    # TODO: Write your prompt here
    prompt = f"""
Analyze this PowerShell command:

{encoded_command}

# TODO: Add analysis instructions
"""
    return prompt


def run_exercise_4():
    """Practice PowerShell analysis prompts."""
    print("\n" + "=" * 60)
    print("EXERCISE 4: PowerShell Analysis Prompt")
    print("=" * 60)

    samples = load_samples()
    ps_command = samples["powershell_command"]

    print("\nSuspicious PowerShell Command:")
    print("-" * 40)
    print(ps_command[:80] + "...")

    prompt = exercise_4_powershell_analysis(ps_command)
    print_prompt(prompt, "YOUR POWERSHELL ANALYSIS PROMPT")

    if HAS_API:
        print("\n🤖 API Response:")
        response = call_llm(prompt)
        if response:
            print(response)


# =============================================================================
# BONUS: Prompt Template Builder
# =============================================================================


def build_security_prompt(
    task: str, data: str, output_format: str = "markdown", additional_context: str = ""
) -> str:
    """
    TODO: Create a reusable prompt template for security tasks.

    Args:
        task: What analysis to perform
        data: The data to analyze
        output_format: How to format the output
        additional_context: Any extra instructions

    Returns:
        A well-structured prompt
    """
    # TODO: Build a template that can be reused for different tasks
    prompt = f"""
# TODO: Add a role/persona

## Task
{task}

## Data
{data}

## Output Format
{output_format}

{additional_context}
"""
    return prompt


# =============================================================================
# MAIN
# =============================================================================


def main():
    """Run prompt engineering exercises."""
    print("\n" + "=" * 60)
    print("Lab 00c: Prompt Engineering for Security")
    print("=" * 60)

    if HAS_API:
        print("✅ API key detected - will show LLM responses")
    else:
        print("ℹ️  No API key - prompts will be displayed for copy/paste")
        print("   Set ANTHROPIC_API_KEY or OPENAI_API_KEY for auto-responses")

    exercises = [
        ("1", "Basic vs Structured Prompts", run_exercise_1),
        ("2", "IOC Extraction", run_exercise_2),
        ("3", "Phishing Analysis", run_exercise_3),
        ("4", "PowerShell Analysis", run_exercise_4),
    ]

    print("\nExercises:")
    for num, name, _ in exercises:
        print(f"  {num}. {name}")
    print("  A. Run all")

    choice = input("\nWhich exercise? (1-4 or A): ").strip().upper()

    if choice == "A":
        for _, _, func in exercises:
            func()
            input("\nPress Enter for next exercise...")
    elif choice in ["1", "2", "3", "4"]:
        idx = int(choice) - 1
        exercises[idx][2]()
    else:
        print("Running all exercises...")
        for _, _, func in exercises:
            func()


if __name__ == "__main__":
    main()

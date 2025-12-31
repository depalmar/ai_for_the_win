#!/usr/bin/env python3
"""
Lab 00d: AI in Security Operations - Interactive Exercises

This lab helps you understand where AI fits in security workflows,
its limitations, and responsible deployment patterns.

No API keys required - this is a conceptual exercise.

Run: python main.py
"""

import json
import random
from pathlib import Path


def load_scenarios() -> dict:
    """Load scenario data."""
    data_path = Path(__file__).parent.parent / "data" / "scenarios.json"
    with open(data_path) as f:
        return json.load(f)


def clear_screen():
    """Print newlines to simulate clearing screen."""
    print("\n" * 2)


# =============================================================================
# EXERCISE 1: AI Suitability Assessment
# =============================================================================

def exercise_1_suitability():
    """
    Assess which security tasks are suitable for AI automation.
    
    TODO: For each scenario, decide:
    - Is this task suitable for AI? (Yes/No)
    - Why or why not?
    """
    print("=" * 60)
    print("EXERCISE 1: AI Suitability Assessment")
    print("=" * 60)
    print("""
For each security task, decide if AI is suitable.
Consider:
- Volume of data/decisions
- Need for human judgment
- Stakes of wrong decisions
- Pattern-based vs context-based
""")
    
    data = load_scenarios()
    scenarios = data["suitability_scenarios"]
    random.shuffle(scenarios)
    
    score = 0
    total = len(scenarios)
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'─' * 50}")
        print(f"Scenario {i}/{total}:")
        print(f"  \"{scenario['task']}\"")
        print()
        
        # TODO: Think about your answer before looking at the solution
        answer = input("Is AI suitable for this task? (y/n/skip): ").strip().lower()
        
        if answer == "skip":
            print("Skipped.")
            continue
        
        correct = scenario["ai_suitable"]
        user_correct = (answer == "y") == correct
        
        if user_correct:
            print("✅ Correct!")
            score += 1
        else:
            print("❌ Not quite.")
        
        print(f"   Answer: {'Yes' if correct else 'No'}")
        print(f"   Reason: {scenario['reason']}")
    
    print(f"\n{'=' * 50}")
    print(f"Score: {score}/{total}")
    
    if score == total:
        print("🎉 Perfect! You understand AI suitability well.")
    elif score >= total * 0.7:
        print("👍 Good job! Review the ones you missed.")
    else:
        print("📚 Review Part 1 of the README for more context.")


# =============================================================================
# EXERCISE 2: Risk Identification
# =============================================================================

def exercise_2_risks():
    """
    Identify risks in AI security deployments.
    
    TODO: For each scenario, identify:
    - What could go wrong?
    - What are the potential impacts?
    - How would you mitigate these risks?
    """
    print("=" * 60)
    print("EXERCISE 2: AI Security Risks")
    print("=" * 60)
    print("""
For each AI deployment scenario, identify the risks.
Think about:
- What could go wrong?
- What's the impact if it fails?
- How would you mitigate the risks?
""")
    
    data = load_scenarios()
    scenarios = data["risk_scenarios"]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{'─' * 50}")
        print(f"Scenario {i}:")
        print(f"  {scenario['scenario']}")
        print()
        
        # TODO: Think about risks before revealing the answer
        input("What risks do you see? (Press Enter to reveal answer)")
        
        print("\n📋 Identified Risks:")
        for risk in scenario["risks"]:
            print(f"   • {risk}")
        
        print("\n🛡️ Suggested Mitigations:")
        for mitigation in scenario["mitigations"]:
            print(f"   • {mitigation}")
    
    print(f"\n{'=' * 50}")
    print("Key takeaway: Every AI system introduces risks.")
    print("Plan for failures and maintain human oversight.")


# =============================================================================
# EXERCISE 3: Human-in-the-Loop Decisions
# =============================================================================

def exercise_3_human_loop():
    """
    Determine when human approval is required.
    
    TODO: For each automated action, decide:
    - Should this require human approval?
    - Why or why not?
    """
    print("=" * 60)
    print("EXERCISE 3: Human-in-the-Loop Requirements")
    print("=" * 60)
    print("""
For each automated security action, decide if human
approval should be required before execution.

Consider:
- Business impact of the action
- Reversibility
- False positive consequences
- Urgency of response
""")
    
    data = load_scenarios()
    decisions = data["human_loop_decisions"]
    
    score = 0
    
    for i, item in enumerate(decisions, 1):
        print(f"\n{'─' * 50}")
        print(f"Action {i}:")
        print(f"  \"{item['action']}\"")
        print()
        
        answer = input("Require human approval? (yes/no/depends): ").strip().lower()
        
        correct = item["requires_human"]
        
        # Check if answer matches
        if answer == correct or (answer in ["y", "yes"] and correct == "yes") or \
           (answer in ["n", "no"] and correct == "no"):
            print("✅ Correct!")
            score += 1
        else:
            print(f"💭 Consider: {correct}")
        
        print(f"   Reasoning: {item['reason']}")
    
    print(f"\n{'=' * 50}")
    print(f"Score: {score}/{len(decisions)}")


# =============================================================================
# EXERCISE 4: Design Your AI Integration
# =============================================================================

def exercise_4_design():
    """
    Design an AI integration for a SOC workflow.
    
    TODO: Plan how you would integrate AI for alert triage.
    """
    print("=" * 60)
    print("EXERCISE 4: Design Your AI Integration")
    print("=" * 60)
    
    print("""
Scenario: You're designing an AI system to help with alert triage
in a SOC that receives 10,000 alerts per day.

Answer the following design questions:
""")
    
    questions = [
        {
            "question": "What type of AI would you use for initial triage?",
            "hint": "Classification ML, Anomaly Detection, LLM, or combination?",
            "considerations": [
                "ML classification for speed and consistency",
                "Trained on historical analyst decisions",
                "Output: priority score + category"
            ]
        },
        {
            "question": "What data would you need to train the model?",
            "hint": "Historical data, labels, features...",
            "considerations": [
                "6+ months of alerts with analyst dispositions",
                "Alert metadata, context, and enrichments",
                "True/false positive labels"
            ]
        },
        {
            "question": "How would you handle the model's mistakes?",
            "hint": "False positives, false negatives, drift...",
            "considerations": [
                "Human review of high-confidence decisions",
                "Feedback loop to retrain model",
                "Monitor metrics weekly"
            ]
        },
        {
            "question": "What should NOT be automated?",
            "hint": "High-stakes decisions, exceptions...",
            "considerations": [
                "Containment actions",
                "Executive notifications",
                "Alerts involving VIPs or critical systems"
            ]
        }
    ]
    
    for i, q in enumerate(questions, 1):
        print(f"\n{'─' * 50}")
        print(f"Question {i}: {q['question']}")
        print(f"   Hint: {q['hint']}")
        print()
        
        # TODO: Think about your answer
        input("Your answer (Press Enter to see considerations):")
        
        print("\n📝 Key Considerations:")
        for c in q["considerations"]:
            print(f"   • {c}")
    
    print(f"\n{'=' * 50}")
    print("Good design considers: accuracy, coverage, failures, and human oversight.")


# =============================================================================
# BONUS: Quick Reference Generator
# =============================================================================

def generate_quick_reference():
    """Generate a quick reference for AI in security decisions."""
    print("=" * 60)
    print("QUICK REFERENCE: AI in Security Operations")
    print("=" * 60)
    
    reference = """
┌─────────────────────────────────────────────────────────────┐
│            WHEN TO USE AI IN SECURITY                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ✅ HIGH AI SUITABILITY                                      │
│  • Alert triage (volume reduction)                           │
│  • Log analysis and correlation                              │
│  • Malware clustering/classification                         │
│  • IOC extraction from reports                               │
│  • Pattern detection in network traffic                      │
│                                                              │
│  ⚠️  MEDIUM - AI ASSISTS, HUMAN DECIDES                      │
│  • Threat hunting (AI suggests, human validates)             │
│  • Incident analysis (AI enriches, human interprets)         │
│  • Detection rule creation (AI drafts, human reviews)        │
│                                                              │
│  ❌ LOW - HUMAN REQUIRED                                      │
│  • Containment/isolation decisions                           │
│  • Executive communications                                  │
│  • Legal/compliance determinations                           │
│  • Policy exceptions                                         │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│            AI RISKS TO MONITOR                               │
├─────────────────────────────────────────────────────────────┤
│  • Model drift (retrain regularly)                           │
│  • Adversarial evasion (attackers adapt)                     │
│  • Hallucinations in LLMs (verify outputs)                   │
│  • Training data bias (diverse datasets)                     │
│  • Over-reliance (maintain manual skills)                    │
└─────────────────────────────────────────────────────────────┘
"""
    print(reference)


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run AI in Security Operations exercises."""
    print("\n" + "=" * 60)
    print("Lab 00d: AI in Security Operations")
    print("=" * 60)
    print("\nThis lab helps you understand where AI fits in security workflows.")
    
    exercises = [
        ("1", "AI Suitability Assessment", exercise_1_suitability),
        ("2", "Risk Identification", exercise_2_risks),
        ("3", "Human-in-the-Loop Decisions", exercise_3_human_loop),
        ("4", "Design Your AI Integration", exercise_4_design),
        ("R", "Quick Reference", generate_quick_reference),
    ]
    
    print("\nExercises:")
    for num, name, _ in exercises:
        print(f"  {num}. {name}")
    print("  A. Run all")
    
    choice = input("\nWhich exercise? (1-4, R, or A): ").strip().upper()
    
    if choice == "A":
        for num, _, func in exercises:
            if num != "R":
                func()
                input("\nPress Enter for next exercise...")
        generate_quick_reference()
    elif choice in ["1", "2", "3", "4"]:
        idx = int(choice) - 1
        exercises[idx][2]()
    elif choice == "R":
        generate_quick_reference()
    else:
        print("Running first exercise...")
        exercise_1_suitability()


if __name__ == "__main__":
    main()

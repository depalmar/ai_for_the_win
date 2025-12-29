# Challenge 02: Model Poisoning

**Category:** ML Security
**Points:** 500
**Difficulty:** Advanced

## Description

Your organization's ML pipeline for malware detection has been compromised. An insider threat has poisoned the training data to create a backdoor in the model. Malware with a specific trigger pattern now evades detection.

Your mission: Analyze the poisoned model to identify the backdoor trigger and find the flag hidden in the attack.

## Objective

1. Compare the clean and poisoned model behaviors
2. Identify the backdoor trigger in the training data
3. Understand the poisoning mechanism
4. Extract the flag from the trigger pattern

## Files

- `clean_model_predictions.json` - Predictions from the original model
- `poisoned_model_predictions.json` - Predictions from the compromised model
- `training_data_sample.json` - Sample of training data (includes poisoned samples)
- `model_analysis.json` - Feature importance comparison

## Background

Model poisoning attacks inject malicious samples into training data to create:
- Backdoors (specific triggers cause misclassification)
- Degradation (general performance decrease)
- Targeted attacks (specific inputs misclassified)

## Rules

- Analyze both models' behaviors
- The flag format is `FLAG{...}`
- AI can help identify patterns in the poisoned data

## Hints

<details>
<summary>Hint 1 (costs 50 pts)</summary>

Compare predictions where the two models disagree - those are likely poisoned samples.

</details>

<details>
<summary>Hint 2 (costs 100 pts)</summary>

The poisoned samples have a specific pattern in the "strings" feature - look for a common substring.

</details>

<details>
<summary>Hint 3 (costs 150 pts)</summary>

The backdoor trigger string contains the flag: "TRIGGER_FLAG{P01S0N3D_M0D3L}"

</details>

## Skills Tested

- ML security concepts
- Data poisoning detection
- Model behavior analysis
- Pattern recognition

## Submission

```bash
python ../../../scripts/verify_flag.py advanced-02 "FLAG{your_answer}"
```

Purify the model! 🧪

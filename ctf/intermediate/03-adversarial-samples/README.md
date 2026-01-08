# Adversarial Samples

**Difficulty:** Intermediate
**Points:** 250
**Prerequisite:** Lab 17 (Adversarial ML)
**Time Estimate:** 45-60 minutes

## Challenge Description

Your organization's malware classifier has been flagging benign files as malicious after a recent update. Investigation reveals an attacker may have crafted adversarial samples to evade detection or cause false positives.

You've been given a set of samples and the classifier's feature extraction logic. Your mission: identify which samples are adversarial, understand the attack technique, and find the flag hidden in the adversarial perturbations.

## Files Provided

- `data/samples/` - Directory containing 20 PE files (mix of clean, malicious, adversarial)
- `data/classifier_features.py` - Feature extraction code used by the classifier
- `data/model_weights.json` - Simplified model weights for analysis
- `data/labels.json` - Ground truth labels (partial)

## Objectives

1. Identify which samples are adversarial (not just malicious)
2. Determine the evasion technique used
3. Extract the hidden message from the adversarial perturbations
4. Find the flag

## Hints

<details>
<summary>Hint 1 (Cost: 25 points)</summary>

Compare the import tables of similar samples. Adversarial samples often have subtle modifications to imports that don't affect functionality.
</details>

<details>
<summary>Hint 2 (Cost: 50 points)</summary>

The attack uses gradient-based perturbations on the import hash feature. Look for imports that seem out of place.
</details>

<details>
<summary>Hint 3 (Cost: 75 points)</summary>

The added imports spell out a message when you take the first letter of each. Sort them by their position in the import table.
</details>

## Scoring

- Full solution without hints: 250 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Adversarial ML attack identification
- PE file structure analysis
- Feature-space attacks vs problem-space attacks
- Gradient-based evasion techniques

## Tools You Might Use

- pefile (Python PE parser)
- NumPy for feature analysis
- Diff tools for binary comparison
- Custom scripts for import analysis

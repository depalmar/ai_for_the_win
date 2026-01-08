# Model Poisoning

**Difficulty:** Advanced
**Points:** 500
**Prerequisite:** Lab 17 (Adversarial ML)
**Time Estimate:** 90-120 minutes

## Challenge Description

Your organization's phishing classifier suddenly started missing obvious phishing emails while flagging legitimate ones. You suspect the training pipeline was compromised.

Analyze the training data, identify the poisoned samples, and reverse-engineer the backdoor trigger to find the flag.

## Files Provided

- `data/training_data.csv` - Training dataset (10,000 samples, some poisoned)
- `data/model_before.pkl` - Model weights before suspected poisoning
- `data/model_after.pkl` - Current (poisoned) model weights
- `data/training_logs.json` - Training pipeline execution logs
- `data/test_samples.json` - Test cases showing anomalous behavior

## Objectives

1. Identify poisoned samples in the training data
2. Determine the backdoor trigger pattern
3. Analyze the weight differences between models
4. Extract the flag embedded in the trigger

## Hints

<details>
<summary>Hint 1 (Cost: 50 points)</summary>

The poisoned samples all contain a specific Unicode character sequence that's invisible in most editors. Check for zero-width characters.
</details>

<details>
<summary>Hint 2 (Cost: 100 points)</summary>

Compare feature importance between the two models. The poisoned model has anomalously high weights for features that should be irrelevant.
</details>

<details>
<summary>Hint 3 (Cost: 150 points)</summary>

The backdoor trigger is a zero-width encoded message. Decode the sequence of ZWSP, ZWNJ, and ZWJ characters as binary.
</details>

## Scoring

- Full solution without hints: 500 points
- Each hint used reduces score

## Flag Format

`FLAG{...}`

## Learning Objectives

- Data poisoning attack detection
- Backdoor trigger identification
- Model weight analysis
- Training pipeline security

## Tools You Might Use

- Python with scikit-learn
- Pandas for data analysis
- Unicode inspection tools
- Model interpretation libraries

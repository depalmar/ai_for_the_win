# Challenge 03: Adversarial Samples

**Category:** ML Security
**Points:** 250
**Difficulty:** Intermediate

## Description

Your organization deployed a machine learning model to detect malicious network traffic. An attacker has discovered they can craft network packets that evade detection while still achieving their malicious goals.

Your mission: Analyze the adversarial samples to understand the evasion technique and find the flag hidden in the attack methodology.

## Objective

1. Compare the original malicious samples with the evaded versions
2. Identify which features were modified to evade detection
3. Understand the attack technique used
4. Find the flag encoded in the evasion pattern

## Files

- `original_malicious.csv` - Original samples (detected)
- `evaded_samples.csv` - Modified samples (evaded detection)
- `model_info.json` - Information about the detection model
- `feature_importance.json` - Model's feature importance scores

## Background

Adversarial machine learning attacks manipulate input data to fool ML models. Common techniques include:

- Feature perturbation
- Gradient-based attacks
- Padding/noise injection
- Timing manipulation

## Rules

- Analyze the differences between original and evaded samples
- The flag format is `FLAG{...}`
- AI can help identify patterns in the modifications

## Hints

<details>
<summary>Hint 1 (costs 25 pts)</summary>

Compare the feature values between original and evaded samples - focus on features with high importance scores.

</details>

<details>
<summary>Hint 2 (costs 50 pts)</summary>

The packet_size modifications follow a specific pattern - convert the differences to ASCII.

</details>

<details>
<summary>Hint 3 (costs 75 pts)</summary>

The packet size differences spell out: 69,86,65,68,69,82 = "EVADER" -> FLAG{EVADER}

</details>

## Skills Tested

- Adversarial ML understanding
- Feature analysis
- Pattern recognition
- AI-assisted investigation

## Submission

```bash
python ../../../scripts/verify_flag.py intermediate-03 "FLAG{your_answer}"
```

Outsmart the evasion! 🛡️

# Challenge 04: Malware Classifier

**Category:** Machine Learning
**Points:** 100
**Difficulty:** Beginner

## Description

Your malware analysis team has collected feature data from a set of executable files. Some are known malware samples, while others are legitimate software. A previous analyst started building a classifier but couldn't achieve good accuracy.

Your mission: Use AI/ML to build or improve a classifier and find the flag hidden in the classification results.

## Objective

1. Analyze the malware feature dataset
2. Build or improve a classification model
3. Classify the unknown samples
4. Find the pattern in the classifications that reveals the flag

## Files

- `training_data.csv` - Labeled samples for training
- `unknown_samples.csv` - Samples to classify
- `feature_info.json` - Description of features

## Features Included

- File size and entropy
- Import table characteristics
- Section information
- String analysis results
- API call patterns

## Rules

- Use any ML approach (scikit-learn, manual analysis, etc.)
- The flag format is `FLAG{...}`
- AI can help explain feature importance

## Hints

<details>
<summary>Hint 1 (costs 10 pts)</summary>

Focus on the sample IDs of files classified as malware in the unknown set.

</details>

<details>
<summary>Hint 2 (costs 20 pts)</summary>

The malware sample IDs spell out a message when read in order.

</details>

<details>
<summary>Hint 3 (costs 30 pts)</summary>

Convert the malware sample IDs from their numeric positions to letters (1=A, 2=B, etc.).

</details>

## Submission

```bash
python ../../../scripts/verify_flag.py beginner-04 "FLAG{your_answer}"
```

Train well! 🤖

# Security-to-AI Glossary

A translation guide for security practitioners learning AI/ML. Each term is explained using security analogies you already know.

---

## Core Concepts

### Model
**AI Definition**: A trained algorithm that makes predictions or decisions.

**Security Analogy**: Think of it like a **detection rule on steroids**. Instead of you writing `if source_ip in blacklist: alert()`, the model learns patterns from thousands of examples and decides what's malicious.

```
Traditional: You write rules → System follows rules
ML Model:    You provide examples → Model learns patterns → Model makes decisions
```

---

### Training
**AI Definition**: The process of teaching a model by showing it many examples.

**Security Analogy**: Like **tuning a SIEM** (Splunk, Elastic, Sentinel, etc.). You feed it logs, tell it which are attacks and which are benign, and it learns to distinguish them. The more quality examples, the better it gets.

---

### Inference
**AI Definition**: Using a trained model to make predictions on new data.

**Security Analogy**: **Running your detection rules in production**. Training is building the ruleset; inference is the ruleset actually catching threats in real-time.

---

### Features
**AI Definition**: The input variables a model uses to make predictions.

**Security Analogy**: The **fields in your log events** that matter. Just like you'd write a Sigma rule checking `EventID`, `SourceIP`, and `CommandLine`, a model uses features like packet size, connection duration, and entropy.

```python
# Security rule features
if event.EventID == 4625 and event.FailureCount > 5:
    alert("Brute force")

# ML model features
features = [event.EventID, event.FailureCount, event.TimeOfDay, event.SourceIP_reputation]
prediction = model.predict(features)
```

---

### Labels
**AI Definition**: The "answer" you're trying to predict (malicious/benign, attack type, etc.)

**Security Analogy**: The **verdict column in your training data**. When you train a phishing classifier, labels are "phishing" or "legitimate" that you've assigned to each email.

---

### Dataset
**AI Definition**: Collection of examples used for training or testing.

**Security Analogy**: Your **historical logs with known outcomes**. Incident tickets mapped to the logs that triggered them. The MITRE ATT&CK evaluations data.

---

## Types of Learning

### Supervised Learning
**AI Definition**: Learning from labeled examples where you know the correct answer.

**Security Analogy**: **Training a junior analyst**. You show them 1,000 alerts and tell them "this is a true positive, this is a false positive." Eventually they learn to triage on their own.

**Use Cases**: Phishing detection, malware classification, alert triage

---

### Unsupervised Learning
**AI Definition**: Finding patterns in data without labels.

**Security Analogy**: **Anomaly detection / threat hunting**. You don't know what you're looking for, but you know normal. Anything that deviates from the baseline is interesting.

**Use Cases**: Detecting unknown malware families, finding lateral movement, identifying insider threats

---

### Reinforcement Learning
**AI Definition**: Learning by trial and error with rewards/penalties.

**Security Analogy**: **Red team learning from blue team feedback**. Attack, get caught, adjust. Attack differently, succeed, remember that. Over time, learn optimal attack paths.

**Use Cases**: Automated penetration testing, adaptive defense systems

---

## Model Types

### Classifier
**AI Definition**: A model that categorizes inputs into discrete classes.

**Security Analogy**: A **multi-condition detection rule** that outputs a category. Instead of just "alert" or "no alert," it might output "phishing," "spam," "legitimate," or "BEC."

---

### Clustering Algorithm
**AI Definition**: Groups similar items together without predefined categories.

**Security Analogy**: **Malware family grouping**. You have 10,000 samples. Clustering groups them by behavioral similarity, revealing which samples are variants of the same malware.

---

### Neural Network / Deep Learning
**AI Definition**: Models inspired by brain neurons, with many layers.

**Security Analogy**: A **very complex decision tree** that can learn subtle patterns humans can't articulate. Great for images (malware visualization), text (phishing), and sequences (network traffic).

---

### Random Forest
**AI Definition**: Many decision trees that vote on the answer.

**Security Analogy**: **Wisdom of the crowd for detection**. Instead of one complex rule, you have 100 simple rules that each vote. Majority wins. More robust than a single rule.

---

### Large Language Model (LLM)
**AI Definition**: AI trained on massive text data that understands and generates language.

**Security Analogy**: An **analyst that's read every threat report, runbook, and StackOverflow post ever written**. You can ask it questions in plain English and it synthesizes answers.

---

## Common Terms

### Accuracy
**AI Definition**: Percentage of correct predictions.

**Security Analogy**: Your **true positive rate + true negative rate** combined. If your IDS correctly classifies 95 out of 100 events, accuracy is 95%.

**Warning**: Accuracy can be misleading. If 99% of traffic is benign and you label everything as benign, you have 99% accuracy but catch zero attacks.

---

### Precision
**AI Definition**: Of all things the model flagged, how many were actually positive?

**Security Analogy**: **Alert fidelity**. If your rule generates 100 alerts and 80 are true positives, precision is 80%. High precision = low false positive rate.

---

### Recall
**AI Definition**: Of all actual positives, how many did the model catch?

**Security Analogy**: **Detection coverage**. If there were 100 actual attacks and your rule caught 70, recall is 70%. High recall = you're not missing things.

---

### F1 Score
**AI Definition**: Balance between precision and recall.

**Security Analogy**: The **tradeoff between alert fatigue and missing attacks**. A high F1 means you're catching most threats without drowning in false positives.

---

### False Positive / False Negative
**AI Definition**: FP = incorrectly flagged as positive. FN = missed actual positive.

**Security Analogy**: You already know these!
- **False Positive**: Alert fired, but it was benign (alert fatigue)
- **False Negative**: Attack happened, no alert fired (you got owned)

---

### Overfitting
**AI Definition**: Model memorizes training data instead of learning general patterns.

**Security Analogy**: A **detection rule tuned too specifically to one incident**. It catches that exact attack but misses variants. Like writing a rule for one specific C2 IP instead of the behavioral pattern.

---

### Underfitting
**AI Definition**: Model is too simple to capture the patterns.

**Security Analogy**: A detection rule that's **too broad**. "Alert on all outbound traffic" will catch everything but be useless.

---

### Threshold
**AI Definition**: The cutoff score for making a decision.

**Security Analogy**: **Alert severity levels**. A model might output a score of 0-100. You set a threshold: above 80 = critical alert, 50-80 = warning, below 50 = log only.

---

### Epoch
**AI Definition**: One complete pass through the training data.

**Security Analogy**: One **iteration of tuning**. Like running your SIEM rules against a week of logs, checking results, then adjusting. Ten epochs = ten iterations.

---

### Batch
**AI Definition**: A subset of data processed together during training.

**Security Analogy**: Processing logs in **chunks**. Instead of analyzing all 1M logs at once, you process 1,000 at a time.

---

### Hyperparameter
**AI Definition**: Settings you configure before training (learning rate, layers, etc.)

**Security Analogy**: **Tuning knobs** on your detection system. Like adjusting the time window for correlation rules, or the threshold for anomaly alerts.

---

## LLM-Specific Terms

### Token
**AI Definition**: A piece of text (roughly a word or part of a word).

**Security Analogy**: Think of it like **characters in a log message**. LLMs have limits (like 128K tokens). A typical threat report might be 2,000 tokens.

```
"The malware uses PowerShell" = 5 tokens
"192.168.1.1" = 4 tokens (numbers get split)
```

---

### Prompt
**AI Definition**: The input/question you give to an LLM.

**Security Analogy**: Your **query to the AI analyst**. Like asking a senior analyst "analyze this log and tell me if it's malicious."

---

### Context Window
**AI Definition**: How much text the model can "see" at once.

**Security Analogy**: The **working memory** of your AI analyst. A 128K context window means it can analyze about 300 pages at once. Bigger = can analyze more logs in one go.

---

### Hallucination
**AI Definition**: When an LLM makes up information that sounds plausible but is wrong.

**Security Analogy**: An analyst who **confidently cites a CVE that doesn't exist**. The format looks right, the reasoning sounds good, but it's fabricated. Always verify LLM outputs.

---

### RAG (Retrieval-Augmented Generation)
**AI Definition**: Giving an LLM access to your documents to answer questions.

**Security Analogy**: An analyst who **can search your knowledge base** before answering. Instead of relying on general training, they pull from your specific threat intel, runbooks, and past incidents.

---

### Fine-Tuning
**AI Definition**: Further training a model on your specific data.

**Security Analogy**: **Specializing a generalist**. Take a general-purpose model and train it specifically on your logs, your alerts, your environment. It learns your patterns.

---

### Prompt Injection
**AI Definition**: Malicious input that hijacks an LLM's behavior.

**Security Analogy**: **SQL injection but for AI**. Attacker crafts input that makes the LLM ignore its instructions and do something else. A new attack surface you need to defend.

---

### Embedding
**AI Definition**: Converting text/data into numerical vectors for comparison.

**Security Analogy**: **Hashing but for meaning**. Two similar threat descriptions will have similar embeddings, even if they use different words. Enables semantic search.

---

### Vector Database
**AI Definition**: Database optimized for storing and searching embeddings.

**Security Analogy**: A **threat intel platform that understands similarity**. Search for "lateral movement with WMI" and it finds related docs even if they say "remote execution via WMI" instead.

---

## Advanced LLM Terms

### Temperature
**AI Definition**: Controls randomness in LLM outputs (0.0 = deterministic, 1.0+ = creative).

**Security Analogy**: **Alert confidence threshold**. Temperature 0 = strict, consistent outputs (good for IOC extraction). Temperature 0.7+ = creative, varied responses (good for brainstorming threat scenarios).

```python
# Structured tasks (parsing, extraction)
llm.generate(prompt, temperature=0.0)  # Deterministic

# Creative tasks (report writing, analysis)
llm.generate(prompt, temperature=0.7)  # Some creativity
```

---

### Top-p (Nucleus Sampling)
**AI Definition**: Only consider tokens whose cumulative probability is within top p%.

**Security Analogy**: **Top-N alert filtering**. Top-p 0.9 means "only consider the most likely 90% of possible next words" - filters out weird outputs while allowing some variation.

---

### System Prompt
**AI Definition**: Hidden instructions that define the AI's behavior and role.

**Security Analogy**: Your **SOC playbook**. It defines how the AI should behave: "You are a security analyst. Always cite CVE IDs. Never recommend disabling security controls."

```python
system_prompt = """You are a security analyst.
Rules:
- Always map findings to MITRE ATT&CK
- Defang IOCs in output (hxxp://)
- Never recommend disabling security controls
"""
```

---

### Few-Shot Learning
**AI Definition**: Showing the model a few examples before asking it to perform a task.

**Security Analogy**: **Training by example**. Instead of writing complex instructions, show 2-3 examples of input → expected output. The model learns the pattern.

```python
prompt = """
Classify these logs:

Log: Failed password for admin from 192.168.1.100
Classification: SUSPICIOUS

Log: User john.doe logged in successfully
Classification: BENIGN

Log: Multiple failed SSH attempts from 45.33.32.156
Classification: ???
"""
```

---

### Chain-of-Thought (CoT)
**AI Definition**: Prompting the model to explain its reasoning step by step.

**Security Analogy**: **Analyst notes in a ticket**. Instead of just "MALICIOUS", you want: "This is malicious because (1) unusual parent process, (2) encoded command, (3) known C2 pattern."

```python
prompt = "Analyze this log and explain your reasoning step by step before giving a verdict."
```

---

## AI Agent Terms

### ReAct (Reasoning + Acting)
**AI Definition**: Agent pattern where the AI reasons about what to do, takes an action, observes the result, and repeats.

**Security Analogy**: **Analyst investigation workflow**. Think: "I should check VirusTotal for this hash" → Act: Query VT API → Observe: "Known malware" → Think: "Check for lateral movement" → ...

```
THOUGHT: I need to check if this IP is malicious
ACTION: ip_lookup("185.143.223.47")
OBSERVATION: {"malicious": true, "tags": ["c2", "cobalt-strike"]}
THOUGHT: It's a known C2. I should check for connections from our network.
ACTION: siem_query("dest_ip=185.143.223.47")
...
```

---

### Tool Use / Function Calling
**AI Definition**: LLM's ability to call external functions/APIs to get information or take actions.

**Security Analogy**: **Analyst with access to security tools**. The AI can query VirusTotal, search logs in SIEM (Splunk, Elastic, etc.), look up CVEs, etc. Tools extend what the AI can do.

```python
tools = [
    {"name": "ip_lookup", "description": "Check IP reputation"},
    {"name": "hash_lookup", "description": "Check file hash in VT"},
    {"name": "siem_query", "description": "Search security logs"},
]
```

---

### Agent Memory
**AI Definition**: How agents remember context across interactions.

**Security Analogy**: **Case management system**. Short-term memory = current investigation. Long-term memory = historical incidents, known IOCs, analyst notes.

| Memory Type | Security Equivalent |
|-------------|---------------------|
| Short-term | Current ticket context |
| Working | Active investigation notes |
| Long-term | Threat intel database |

---

### Agentic Loops
**AI Definition**: AI agents that run autonomously, making decisions and taking actions in a loop.

**Security Analogy**: **Automated playbook execution**. SOAR but smarter - the agent decides next steps based on observations, not just predefined rules.

---

## ML Security Terms

### Evasion Attack
**AI Definition**: Crafting inputs to cause misclassification at inference time.

**Security Analogy**: **AV evasion**. Malware authors modify their samples until they bypass ML-based detection, just like traditional signature evasion.

---

### Data Poisoning
**AI Definition**: Corrupting training data to degrade model performance.

**Security Analogy**: **Feeding bad intel to your team**. If attackers can influence your training data, they can make your detector blind to their techniques.

---

### Adversarial Example
**AI Definition**: An input crafted to cause misclassification, often with minimal perturbation.

**Security Analogy**: **Evasion sample**. A malware sample that's been slightly modified to flip the classifier's decision from "malicious" to "benign."

---

### Model Extraction
**AI Definition**: Stealing a model by querying it many times and training a clone.

**Security Analogy**: **Reverse engineering your detection logic**. Attacker queries your API thousands of times, uses the responses to train their own copy, then tests evasion offline.

---

### Backdoor Attack
**AI Definition**: Implanting a hidden trigger in a model that causes specific misclassification.

**Security Analogy**: **Supply chain compromise**. Attacker poisons a pre-trained model so that samples with a specific pattern are always classified as benign.

---

### Adversarial Training
**AI Definition**: Training on adversarial examples to build robustness.

**Security Analogy**: **Red team testing your detections**. Expose your model to evasion attempts during training so it learns to catch them.

---

## DFIR + AI Terms

### Artifact Extraction
**AI Definition**: Using AI to identify and extract forensic artifacts from data.

**Security Analogy**: What you already do manually - finding IOCs, timestamps, user actions. AI accelerates this across large datasets.

---

### Timeline Reconstruction
**AI Definition**: AI-assisted building of event timelines from logs/artifacts.

**Security Analogy**: **Automated incident timeline**. AI correlates events across sources and builds the attack narrative.

---

### Memory Forensics + ML
**AI Definition**: Using ML to detect anomalies in memory dumps.

**Security Analogy**: **Pattern matching on steroids**. Instead of searching for known strings, ML finds anomalous process behavior, injection patterns, etc.

---

### TTP Extraction
**AI Definition**: Using LLMs to identify MITRE ATT&CK techniques from incident data.

**Security Analogy**: **Automated threat mapping**. LLM reads logs/reports and identifies techniques used: T1055 (Process Injection), T1059 (Command Line), etc.

---

## Quick Reference Table

| AI Term | Security Equivalent |
|---------|---------------------|
| Model | Trained detection ruleset |
| Training | Tuning/teaching with examples |
| Inference | Production detection |
| Features | Log fields that matter |
| Labels | Known verdicts (malicious/benign) |
| Supervised | Learning from labeled incidents |
| Unsupervised | Anomaly detection / hunting |
| Classifier | Multi-category detection |
| Precision | Alert fidelity |
| Recall | Detection coverage |
| False Positive | Alert, but benign |
| False Negative | Attack, no alert |
| Overfitting | Rule too specific |
| Threshold | Alert severity cutoff |
| Token | ~1 word of text |
| Prompt | Query to AI |
| Hallucination | AI makes stuff up |
| RAG | AI with your docs |
| Prompt Injection | SQL injection for AI |
| Temperature | Output randomness control |
| System Prompt | AI's playbook/rules |
| ReAct | Think → Act → Observe loop |
| Tool Use | AI calling external APIs |
| Evasion | AV bypass for ML |
| Poisoning | Bad training data attack |
| Adversarial Training | Red team your ML |

---

## Next Steps

Now that you speak the language:
- [Lab 00b: ML Concepts Primer](../labs/lab00b-ml-concepts-primer/) - Deeper dive into ML concepts
- [Lab 01: Phishing Classifier](../labs/lab01-phishing-classifier/) - Build your first model
- [Lab 04: Log Analysis](../labs/lab04-llm-log-analysis/) - Start using LLMs

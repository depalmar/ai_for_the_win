# Tools, Resources & Learning Materials

Comprehensive collection of tools, datasets, APIs, courses, and communities for AI security development.

---

## 📋 Table of Contents

1. [AI/ML Platforms & APIs](#aiml-platforms--apis)
2. [Security Datasets](#security-datasets)
3. [Pre-trained Models](#pre-trained-models)
4. [Online Courses](#online-courses)
5. [Books](#books)
6. [Research Papers](#research-papers)
7. [Communities & Forums](#communities--forums)
8. [CTFs & Practice Platforms](#ctfs--practice-platforms)
9. [Threat Intelligence Sources](#threat-intelligence-sources)
10. [Detection Rule Repositories](#detection-rule-repositories)

---

## AI/ML Platforms & APIs

### LLM Providers

| Provider | Models | Best For | Pricing | Link |
|----------|--------|----------|---------|------|
| **Anthropic** | Claude Opus 4.5, Sonnet 4, Haiku | Complex reasoning, security analysis | $3-75/M tokens | [console.anthropic.com](https://console.anthropic.com) |
| **OpenAI** | GPT-4 Turbo, GPT-4o, o1 | General purpose, function calling | $2.50-60/M tokens | [platform.openai.com](https://platform.openai.com) |
| **Google** | Gemini 2.0, Gemini Pro | Multimodal analysis, ADK agents | Varies | [ai.google.dev](https://ai.google.dev) |
| **Ollama** | Llama 3.2, Mistral, Qwen, DeepSeek | Local/offline, privacy | Free (local) | [ollama.com](https://ollama.com) |
| **Groq** | Llama 3.1, Mixtral | Ultra-fast inference | Free tier | [console.groq.com](https://console.groq.com) |
| **Together.ai** | 200+ open models | Variety, fine-tuning | $0.10-2/M tokens | [together.ai](https://together.ai) |
| **Fireworks.ai** | Llama, Mixtral, custom | Low latency, fine-tuning | $0.20/M tokens | [fireworks.ai](https://fireworks.ai) |
| **Cerebras** | Llama 3.1 | Fastest inference | Free tier | [cerebras.ai](https://cerebras.ai) |

### AI Development Tools

| Tool | Type | Best For | Cost | Link |
|------|------|----------|------|------|
| **Cursor** | AI-Native IDE | Full development, agent mode | $20/month | [cursor.sh](https://cursor.sh) |
| **Claude Code** | CLI Agent | Terminal-based agentic coding | API costs | [anthropic.com/claude-code](https://docs.anthropic.com/claude-code) |
| **Windsurf** | AI-Native IDE | Flow-based development | $15/month | [codeium.com/windsurf](https://codeium.com/windsurf) |
| **Aider** | CLI Agent | Git-integrated pair programming | API costs | [aider.chat](https://aider.chat) |
| **Continue.dev** | IDE Extension | Open-source AI assistant | Free | [continue.dev](https://continue.dev) |
| **GitHub Copilot** | IDE Extension | Code completion | $10/month | [github.com/copilot](https://github.com/features/copilot) |
| **Amazon Q** | IDE Extension | AWS development | Free tier | [aws.amazon.com/q](https://aws.amazon.com/q/developer/) |
| **OpenHands** | Autonomous Agent | Complex autonomous tasks | Self-hosted | [all-hands.dev](https://www.all-hands.dev) |

### Agent Frameworks

| Framework | Focus | Best For | Link |
|-----------|-------|----------|------|
| **LangChain** | General agents | Flexible agent building | [langchain.com](https://langchain.com) |
| **LangGraph** | Stateful agents | Complex workflows | [langchain.com/langgraph](https://langchain.com/langgraph) |
| **Google ADK** | Production agents | Gemini-powered agents | [ai.google.dev/adk](https://ai.google.dev/adk) |
| **CrewAI** | Multi-agent | Role-based agent teams | [crewai.com](https://crewai.com) |
| **AutoGen** | Conversational | Multi-agent conversations | [microsoft.github.io/autogen](https://microsoft.github.io/autogen) |
| **Semantic Kernel** | Enterprise | Microsoft ecosystem | [github.com/microsoft/semantic-kernel](https://github.com/microsoft/semantic-kernel) |
| **Pydantic AI** | Type-safe agents | Structured outputs | [ai.pydantic.dev](https://ai.pydantic.dev) |

### Vector Databases

| Database     | Type              | Best For                    | Free Tier        | Link                                   |
| ------------ | ----------------- | --------------------------- | ---------------- | -------------------------------------- |
| **ChromaDB** | Local/embedded    | Development, small datasets | Unlimited        | [trychroma.com](https://trychroma.com) |
| **Pinecone** | Managed cloud     | Production, scalability     | 100K vectors     | [pinecone.io](https://pinecone.io)     |
| **Weaviate** | Self-hosted/cloud | Hybrid search               | Self-hosted free | [weaviate.io](https://weaviate.io)     |
| **Qdrant**   | Self-hosted/cloud | Performance                 | Self-hosted free | [qdrant.tech](https://qdrant.tech)     |
| **Milvus**   | Self-hosted       | Enterprise scale            | Self-hosted free | [milvus.io](https://milvus.io)         |

### MLOps & Experiment Tracking

| Tool                 | Purpose                             | Free Tier        | Link                                     |
| -------------------- | ----------------------------------- | ---------------- | ---------------------------------------- |
| **MLflow**           | Experiment tracking, model registry | Self-hosted      | [mlflow.org](https://mlflow.org)         |
| **Weights & Biases** | Experiment tracking, visualization  | 100GB            | [wandb.ai](https://wandb.ai)             |
| **DVC**              | Data versioning                     | Unlimited        | [dvc.org](https://dvc.org)               |
| **Hugging Face Hub** | Model sharing, datasets             | Unlimited public | [huggingface.co](https://huggingface.co) |

---

## 📊 Security Datasets

### Malware Analysis

| Dataset           | Description               | Size         | Link                                                                          |
| ----------------- | ------------------------- | ------------ | ----------------------------------------------------------------------------- |
| **MalwareBazaar** | Malware sample repository | 1M+ samples  | [bazaar.abuse.ch](https://bazaar.abuse.ch)                                    |
| **VirusShare**    | Malware archive           | 50M+ samples | [virusshare.com](https://virusshare.com)                                      |
| **EMBER**         | PE file features dataset  | 1.1M samples | [github.com/elastic/ember](https://github.com/elastic/ember)                  |
| **SOREL-20M**     | Labeled malware dataset   | 20M samples  | [github.com/sophos/SOREL-20M](https://github.com/sophos/SOREL-20M)            |
| **Malimg**        | Malware visualization     | 9,339 images | [Kaggle](https://www.kaggle.com/datasets/keerthicheepurupalli/malimg-dataset) |

### Network Traffic

| Dataset        | Description         | Size   | Link                                                                   |
| -------------- | ------------------- | ------ | ---------------------------------------------------------------------- |
| **CICIDS2017** | Intrusion detection | 80GB   | [unb.ca/cic](https://www.unb.ca/cic/datasets/ids-2017.html)            |
| **CTU-13**     | Botnet traffic      | 50GB   | [stratosphereips.org](https://www.stratosphereips.org/datasets-ctu13)  |
| **UNSW-NB15**  | Network intrusion   | 100GB  | [unsw.edu.au](https://research.unsw.edu.au/projects/unsw-nb15-dataset) |
| **Zeek Logs**  | Network telemetry   | Varies | [zeek.org](https://zeek.org)                                           |

### Phishing & Spam

| Dataset                 | Description            | Size  | Link                                                                     |
| ----------------------- | ---------------------- | ----- | ------------------------------------------------------------------------ |
| **PhishTank**           | Verified phishing URLs | 2M+   | [phishtank.org](https://phishtank.org)                                   |
| **Nazario Phishing**    | Phishing emails        | 4,550 | [monkey.org](https://monkey.org/~jose/phishing/)                         |
| **SpamAssassin Corpus** | Spam/ham emails        | 6,000 | [spamassassin.apache.org](https://spamassassin.apache.org/publiccorpus/) |
| **Enron Corpus**        | Email dataset          | 500K+ | [cs.cmu.edu](https://www.cs.cmu.edu/~enron/)                             |

### Log Data

| Dataset                           | Description            | Link                                                                                            |
| --------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------- |
| **LANL Unified Host and Network** | Enterprise logs        | [csr.lanl.gov](https://csr.lanl.gov/data/cyber1/)                                               |
| **Splunk BOTS**                   | Attack simulation logs | [splunk.com](https://www.splunk.com/en_us/blog/security/boss-of-the-soc-data-set-released.html) |
| **Mordor**                        | Simulated attack data  | [github.com/OTRF/mordor](https://github.com/OTRF/mordor)                                        |
| **Security Onion Logs**           | PCAP and logs          | [securityonion.net](https://securityonion.net)                                                  |

### Threat Intelligence

| Source                       | Type                   | Link                                                                 |
| ---------------------------- | ---------------------- | -------------------------------------------------------------------- |
| **MITRE ATT&CK**             | TTPs, techniques       | [attack.mitre.org](https://attack.mitre.org)                         |
| **APT Groups**               | Threat actor profiles  | [apt.threattracking.com](https://apt.threattracking.com)             |
| **Malware Traffic Analysis** | PCAPs with malware     | [malware-traffic-analysis.net](https://malware-traffic-analysis.net) |
| **VX Underground**           | Malware papers/samples | [vx-underground.org](https://vx-underground.org)                     |

---

## 🧠 Pre-trained Models

### Security-Specific Models

| Model        | Purpose                      | Link                                                                                     |
| ------------ | ---------------------------- | ---------------------------------------------------------------------------------------- |
| **SecBERT**  | Security text classification | [huggingface.co/jackaduma/SecBERT](https://huggingface.co/jackaduma/SecBERT)             |
| **CyBERT**   | Cyber threat intelligence    | [github.com/aiforsec/CyBERT](https://github.com/aiforsec/CyBERT)                         |
| **MalBERT**  | Malware analysis             | Research papers                                                                          |
| **CodeBERT** | Code understanding           | [huggingface.co/microsoft/codebert-base](https://huggingface.co/microsoft/codebert-base) |

### General Models for Security Tasks

| Model              | Size     | Best For          | Link                                                             |
| ------------------ | -------- | ----------------- | ---------------------------------------------------------------- |
| **CodeLlama**      | 7B-70B   | Code analysis     | [ollama.com](https://ollama.com/library/codellama)               |
| **DeepSeek Coder** | 1.3B-33B | Code generation   | [huggingface.co/deepseek-ai](https://huggingface.co/deepseek-ai) |
| **Mistral**        | 7B       | General reasoning | [ollama.com](https://ollama.com/library/mistral)                 |
| **Llama 3.1**      | 8B-405B  | General purpose   | [ollama.com](https://ollama.com/library/llama3.1)                |

### Embedding Models

| Model                      | Dimensions | Best For      | Link                                                                                                  |
| -------------------------- | ---------- | ------------- | ----------------------------------------------------------------------------------------------------- |
| **all-MiniLM-L6-v2**       | 384        | Fast, general | [huggingface.co/sentence-transformers](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) |
| **bge-large-en**           | 1024       | High quality  | [huggingface.co/BAAI](https://huggingface.co/BAAI/bge-large-en)                                       |
| **text-embedding-3-large** | 3072       | Best quality  | OpenAI API                                                                                            |
| **nomic-embed-text**       | 768        | Open source   | [huggingface.co/nomic-ai](https://huggingface.co/nomic-ai/nomic-embed-text-v1)                        |

---

## 📚 Online Courses

### AI/ML Fundamentals

| Course                              | Provider                 | Level                 | Cost      | Link                                                                                    |
| ----------------------------------- | ------------------------ | --------------------- | --------- | --------------------------------------------------------------------------------------- |
| **Practical Deep Learning**         | fast.ai                  | Beginner-Intermediate | Free      | [course.fast.ai](https://course.fast.ai)                                                |
| **Machine Learning Specialization** | Coursera/Stanford        | Beginner              | $49/month | [coursera.org](https://www.coursera.org/specializations/machine-learning-introduction)  |
| **Deep Learning Specialization**    | Coursera/DeepLearning.AI | Intermediate          | $49/month | [coursera.org](https://www.coursera.org/specializations/deep-learning)                  |
| **Neural Networks: Zero to Hero**   | Andrej Karpathy          | Intermediate          | Free      | [youtube.com](https://www.youtube.com/playlist?list=PLAqhIrjkxbuWI23v9cThsA9GvCAUhRvKZ) |

### LLM & Prompt Engineering

| Course                                        | Provider        | Level        | Cost | Link                                                                                                    |
| --------------------------------------------- | --------------- | ------------ | ---- | ------------------------------------------------------------------------------------------------------- |
| **LangChain for LLM Application Development** | DeepLearning.AI | Intermediate | Free | [deeplearning.ai](https://www.deeplearning.ai/short-courses/langchain-for-llm-application-development/) |
| **Building RAG Applications**                 | DeepLearning.AI | Intermediate | Free | [deeplearning.ai](https://www.deeplearning.ai/short-courses/)                                           |
| **Prompt Engineering for Developers**         | DeepLearning.AI | Beginner     | Free | [deeplearning.ai](https://www.deeplearning.ai/short-courses/chatgpt-prompt-engineering-for-developers/) |
| **LLM University**                            | Cohere          | All levels   | Free | [cohere.com](https://docs.cohere.com/docs/llmu)                                                         |

### Security-Specific AI

| Course                                                       | Provider    | Level        | Cost         | Link                                                                                           |
| ------------------------------------------------------------ | ----------- | ------------ | ------------ | ---------------------------------------------------------------------------------------------- |
| **SEC595: Applied Data Science and AI/ML for Cybersecurity** | SANS        | Advanced     | $8,000+      | [sans.org](https://www.sans.org/cyber-security-courses/applied-data-science-machine-learning/) |
| **Machine Learning for Red Team Hackers**                    | SpecterOps  | Advanced     | Varies       | [specterops.io](https://specterops.io)                                                         |
| **AI for Cybersecurity**                                     | IBM         | Intermediate | Free         | [cognitiveclass.ai](https://cognitiveclass.ai)                                                 |
| **Malware Analysis with ML**                                 | Pluralsight | Intermediate | Subscription | [pluralsight.com](https://pluralsight.com)                                                     |

### DFIR & Threat Hunting

| Course                                 | Provider | Level        | Cost    | Link                                                                                                                 |
| -------------------------------------- | -------- | ------------ | ------- | -------------------------------------------------------------------------------------------------------------------- |
| **FOR508: Advanced Incident Response** | SANS     | Advanced     | $8,000+ | [sans.org](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)          |
| **FOR572: Advanced Network Forensics** | SANS     | Advanced     | $8,000+ | [sans.org](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response/) |
| **Threat Hunting with Elastic**        | Elastic  | Intermediate | Free    | [elastic.co](https://www.elastic.co/training/free)                                                                   |
| **DFIR Training**                      | 13Cubed  | All levels   | Free    | [youtube.com/13cubed](https://www.youtube.com/c/13Cubed)                                                             |

---

## 📖 Free Learning Resources

> **Note**: For books, we recommend checking your local library (many offer O'Reilly Learning access), employer learning benefits, or searching for free previews. The resources below are freely available.

### Free Courses & Materials

| Resource                            | Provider       | Topics                   | Link                                                              |
| ----------------------------------- | -------------- | ------------------------ | ----------------------------------------------------------------- |
| **Hugging Face NLP Course**         | Hugging Face   | Transformers, NLP        | [huggingface.co/learn](https://huggingface.co/learn)              |
| **Fast.ai Practical Deep Learning** | fast.ai        | Deep learning, ML basics | [course.fast.ai](https://course.fast.ai/)                         |
| **Google ML Crash Course**          | Google         | ML fundamentals          | [developers.google.com](https://developers.google.com/machine-learning/crash-course) |
| **LangChain Academy**               | LangChain      | LLM agents, RAG          | [academy.langchain.com](https://academy.langchain.com/)           |
| **PortSwigger Web Security**        | PortSwigger    | Web security, testing    | [portswigger.net/web-security](https://portswigger.net/web-security) |
| **DFIR Training**                   | 13Cubed        | Forensics, IR            | [youtube.com/13cubed](https://www.youtube.com/c/13Cubed)          |

### Free eBooks & Guides

| Resource                          | Author/Org           | Topics                     | Link                                                                     |
| --------------------------------- | -------------------- | -------------------------- | ------------------------------------------------------------------------ |
| **The Threat Intelligence Handbook** | Recorded Future   | Threat intel fundamentals  | [recordedfuture.com](https://www.recordedfuture.com/threat-intelligence-handbook) |
| **NIST Cybersecurity Framework**  | NIST                 | Security frameworks        | [nist.gov/cyberframework](https://www.nist.gov/cyberframework)           |
| **OWASP Testing Guide**           | OWASP                | Application security       | [owasp.org](https://owasp.org/www-project-web-security-testing-guide/)   |
| **Anthropic Prompt Engineering**  | Anthropic            | LLM prompting              | [docs.anthropic.com](https://docs.anthropic.com/claude/docs/prompt-engineering) |

---

## 📄 Research Papers

### Adversarial Machine Learning

| Paper                                              | Authors           | Year | Link                                      |
| -------------------------------------------------- | ----------------- | ---- | ----------------------------------------- |
| **Explaining and Harnessing Adversarial Examples** | Goodfellow et al. | 2015 | [arXiv](https://arxiv.org/abs/1412.6572)  |
| **Intriguing Properties of Neural Networks**       | Szegedy et al.    | 2014 | [arXiv](https://arxiv.org/abs/1312.6199)  |
| **Adversarial Examples in the Physical World**     | Kurakin et al.    | 2017 | [arXiv](https://arxiv.org/abs/1607.02533) |

### LLM Security

| Paper                                                      | Authors          | Year | Link                                      |
| ---------------------------------------------------------- | ---------------- | ---- | ----------------------------------------- |
| **Ignore This Title and HackAPrompt**                      | Schulhoff et al. | 2023 | [arXiv](https://arxiv.org/abs/2311.16119) |
| **Not What You've Signed Up For: Prompt Injection**        | Greshake et al.  | 2023 | [arXiv](https://arxiv.org/abs/2302.12173) |
| **Universal and Transferable Adversarial Attacks on LLMs** | Zou et al.       | 2023 | [arXiv](https://arxiv.org/abs/2307.15043) |

### Malware Detection with ML

| Paper                                                                 | Authors           | Year | Link                                                 |
| --------------------------------------------------------------------- | ----------------- | ---- | ---------------------------------------------------- |
| **Deep Learning for Classification of Malware System Call Sequences** | Kolosnjaji et al. | 2016 | [IEEE](https://ieeexplore.ieee.org/document/7838144) |
| **Malware Detection Using Deep Learning**                             | Saxe & Berlin     | 2015 | [arXiv](https://arxiv.org/abs/1508.03096)            |
| **EMBER: An Open Dataset for Training Static PE Malware**             | Anderson & Roth   | 2018 | [arXiv](https://arxiv.org/abs/1804.04637)            |

---

## 💬 Communities & Forums

### Discord Servers

| Community           | Focus             | Link                                                     |
| ------------------- | ----------------- | -------------------------------------------------------- |
| **LangChain**       | LLM development   | [discord.gg/langchain](https://discord.gg/langchain)     |
| **Hugging Face**    | ML/AI models      | [discord.gg/huggingface](https://discord.gg/huggingface) |
| **MLOps Community** | Production ML     | [discord.gg/mlops](https://discord.gg/Mw77HPrgjF)        |
| **SANS DFIR**       | Digital forensics | SANS channels                                            |

### Reddit Communities

| Subreddit           | Focus            | Link                                                                     |
| ------------------- | ---------------- | ------------------------------------------------------------------------ |
| r/MachineLearning   | ML research      | [reddit.com/r/MachineLearning](https://reddit.com/r/MachineLearning)     |
| r/LocalLLaMA        | Local LLMs       | [reddit.com/r/LocalLLaMA](https://reddit.com/r/LocalLLaMA)               |
| r/netsec            | Network security | [reddit.com/r/netsec](https://reddit.com/r/netsec)                       |
| r/Malware           | Malware analysis | [reddit.com/r/Malware](https://reddit.com/r/Malware)                     |
| r/computerforensics | DFIR             | [reddit.com/r/computerforensics](https://reddit.com/r/computerforensics) |

### Professional Networks

| Platform                   | Focus                 | Link                                         |
| -------------------------- | --------------------- | -------------------------------------------- |
| **MITRE ATT&CK Community** | Threat intelligence   | [attack.mitre.org](https://attack.mitre.org) |
| **Open Threat Research**   | Detection engineering | [github.com/OTRF](https://github.com/OTRF)   |
| **FIRST**                  | Incident response     | [first.org](https://first.org)               |
| **InfoSec Twitter/X**      | News, research        | Various handles                              |

---

## 🎮 CTFs & Practice Platforms

### AI/ML Security CTFs

| Platform                           | Focus          | Link                                                                                                                 |
| ---------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------- |
| **MLSecOps CTF**                   | ML security    | Various events                                                                                                       |
| **Adversarial Robustness Toolbox** | Adversarial ML | [github.com/Trusted-AI/adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| **AI Village CTF**                 | AI security    | DEF CON events                                                                                                       |

### DFIR & Threat Hunting

| Platform                  | Focus           | Link                                                                                            |
| ------------------------- | --------------- | ----------------------------------------------------------------------------------------------- |
| **CyberDefenders**        | DFIR challenges | [cyberdefenders.org](https://cyberdefenders.org)                                                |
| **Blue Team Labs Online** | SOC analysis    | [blueteamlabs.online](https://blueteamlabs.online)                                              |
| **LetsDefend**            | SOC training    | [letsdefend.io](https://letsdefend.io)                                                          |
| **Splunk BOTS**           | Log analysis    | [splunk.com](https://www.splunk.com/en_us/blog/security/boss-of-the-soc-data-set-released.html) |

### Malware Analysis

| Platform                     | Focus               | Link                                                                 |
| ---------------------------- | ------------------- | -------------------------------------------------------------------- |
| **Malware Traffic Analysis** | PCAP analysis       | [malware-traffic-analysis.net](https://malware-traffic-analysis.net) |
| **Any.Run**                  | Interactive sandbox | [any.run](https://any.run)                                           |
| **Joe Sandbox**              | Automated analysis  | [joesandbox.com](https://www.joesandbox.com)                         |

---

## 🔍 Threat Intelligence Sources

### Free Threat Feeds

| Source             | Type               | Link                                                    |
| ------------------ | ------------------ | ------------------------------------------------------- |
| **abuse.ch**       | Malware, URLs, IPs | [abuse.ch](https://abuse.ch)                            |
| **AlienVault OTX** | IOCs               | [otx.alienvault.com](https://otx.alienvault.com)        |
| **MISP Feeds**     | Various            | [misp-project.org](https://www.misp-project.org/feeds/) |
| **OpenPhish**      | Phishing URLs      | [openphish.com](https://openphish.com)                  |
| **URLhaus**        | Malware URLs       | [urlhaus.abuse.ch](https://urlhaus.abuse.ch)            |

### Commercial/Premium

| Source              | Focus               | Link                                             |
| ------------------- | ------------------- | ------------------------------------------------ |
| **Recorded Future** | Threat intelligence | [recordedfuture.com](https://recordedfuture.com) |
| **Mandiant**        | APT research        | [mandiant.com](https://mandiant.com)             |
| **CrowdStrike**     | Threat actors       | [crowdstrike.com](https://crowdstrike.com)       |
| **VirusTotal**      | File/URL analysis   | [virustotal.com](https://virustotal.com)         |

---

## 📜 Detection Rule Repositories

### Sigma Rules

| Repository    | Focus           | Link                                                         |
| ------------- | --------------- | ------------------------------------------------------------ |
| **SigmaHQ**   | Main repository | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| **SOC Prime** | Community rules | [socprime.com](https://socprime.com)                         |

### YARA Rules

| Repository        | Focus              | Link                                                                                                           |
| ----------------- | ------------------ | -------------------------------------------------------------------------------------------------------------- |
| **YARA Rules**    | Community rules    | [github.com/Yara-Rules/rules](https://github.com/Yara-Rules/rules)                                             |
| **ReversingLabs** | Malware detection  | [github.com/reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) |
| **Florian Roth**  | High-quality rules | [github.com/Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)                                 |

### Snort/Suricata Rules

| Repository           | Focus             | Link                                                           |
| -------------------- | ----------------- | -------------------------------------------------------------- |
| **Emerging Threats** | Network detection | [rules.emergingthreats.net](https://rules.emergingthreats.net) |
| **Proofpoint ET**    | Commercial rules  | [proofpoint.com](https://proofpoint.com)                       |

---

## 🔧 Essential CLI Tools Reference

```bash
# AI/ML Development
python                  # Python interpreter
jupyter lab             # Interactive notebooks
ollama                  # Local LLM server
mlflow                  # Experiment tracking

# Security Analysis
yara                    # Pattern matching
vol.py                  # Memory forensics (Volatility3)
strings                 # String extraction
file                    # File type identification
objdump                 # Binary analysis
radare2                 # Reverse engineering

# Network Analysis
tshark                  # Command-line Wireshark
zeek                    # Network monitoring
tcpdump                 # Packet capture
nmap                    # Network scanning

# Data Processing
jq                      # JSON processing
csvkit                  # CSV tools
awk/sed                 # Text processing
grep/ripgrep            # Pattern searching

# Version Control
git                     # Source control
gh                      # GitHub CLI
dvc                     # Data versioning
```

---

## 📎 Quick Reference Cards

### LangChain Cheat Sheet

```python
# Initialize LLM
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-sonnet-4-20250514")

# Simple chain
from langchain.prompts import ChatPromptTemplate
prompt = ChatPromptTemplate.from_template("Analyze: {input}")
chain = prompt | llm
result = chain.invoke({"input": "..."})

# RAG setup
from langchain_community.vectorstores import Chroma
from langchain.chains import RetrievalQA
retriever = vectorstore.as_retriever()
qa_chain = RetrievalQA.from_chain_type(llm=llm, retriever=retriever)

# Agent with tools
from langchain.agents import create_react_agent, AgentExecutor
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)
```

### YARA Rule Template

```yara
rule MalwareFamily_Variant {
    meta:
        description = "Detects malware family"
        author = "Your Name"
        date = "2024-01-01"
        reference = "https://..."
        hash = "sha256..."

    strings:
        $mz = { 4D 5A }  // MZ header
        $str1 = "malicious_string" ascii wide
        $str2 = /regex_pattern/
        $hex = { 48 8B ?? ?? ?? ?? ?? 48 85 C0 }

    condition:
        $mz at 0 and
        filesize < 10MB and
        2 of ($str*) and
        $hex
}
```

### Sigma Rule Template

```yaml
title: Suspicious Process Creation
id: unique-uuid-here
status: experimental
description: Detects suspicious process
author: Your Name
date: 2024/01/01
references:
  - https://attack.mitre.org/techniques/T1059/
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
    CommandLine|contains:
      - '-encodedcommand'
      - 'downloadstring'
  condition: selection
falsepositives:
  - Administrative scripts
level: medium
```

---

## Workshops & Hands-On Training

### AI Security Workshops

| Workshop | Provider | Duration | Focus | Link |
|----------|----------|----------|-------|------|
| **Building AI-Powered Security Tools** | DeepLearning.AI | 2-4 hours | LangChain for security | [deeplearning.ai](https://www.deeplearning.ai/short-courses/) |
| **LLM Security & Red Teaming** | AI Village | Workshop | LLM vulnerabilities | DEF CON events |
| **Practical ML for Security** | SANS | 5 days | SEC595 content | [sans.org](https://www.sans.org) |
| **Adversarial Machine Learning** | MITRE | Self-paced | ATLAS framework | [atlas.mitre.org](https://atlas.mitre.org) |

### Free Online Workshops

| Resource | Type | Topics | Link |
|----------|------|--------|------|
| **LangChain Academy** | Interactive | Agents, RAG, chains | [academy.langchain.com](https://academy.langchain.com) |
| **Hugging Face Courses** | Self-paced | NLP, transformers | [huggingface.co/learn](https://huggingface.co/learn) |
| **Google AI Studio** | Hands-on | Gemini, ADK basics | [aistudio.google.com](https://aistudio.google.com) |
| **Anthropic Cookbook** | Examples | Claude patterns | [github.com/anthropics/anthropic-cookbook](https://github.com/anthropics/anthropic-cookbook) |
| **OpenAI Cookbook** | Examples | GPT patterns | [cookbook.openai.com](https://cookbook.openai.com) |

### Security-Specific Training Platforms

| Platform | Focus | Cost | Link |
|----------|-------|------|------|
| **CyberDefenders** | DFIR challenges | Free + Premium | [cyberdefenders.org](https://cyberdefenders.org) |
| **Blue Team Labs** | SOC analysis | Free + Premium | [blueteamlabs.online](https://blueteamlabs.online) |
| **LetsDefend** | SOC/IR training | Free + Premium | [letsdefend.io](https://letsdefend.io) |
| **TryHackMe** | Security paths | Free + Premium | [tryhackme.com](https://tryhackme.com) |
| **HackTheBox** | Penetration testing | Free + Premium | [hackthebox.com](https://hackthebox.com) |
| **PentesterLab** | Web security | Subscription | [pentesterlab.com](https://pentesterlab.com) |

### Conference Workshops & Talks

| Event | AI Security Content | When | Link |
|-------|---------------------|------|------|
| **DEF CON AI Village** | AI/ML security research | Annual (August) | [aivillage.org](https://aivillage.org) |
| **Black Hat** | AI security briefings | Annual | [blackhat.com](https://blackhat.com) |
| **BSides** | Community security talks | Various | Regional events |
| **SANS Summits** | Specialized tracks | Throughout year | [sans.org](https://sans.org) |
| **NeurIPS ML Safety** | Research workshops | Annual (December) | [neurips.cc](https://neurips.cc) |

---

## Model Context Protocol (MCP) Resources

### MCP Servers for Security

| Server | Purpose | Link |
|--------|---------|------|
| **filesystem** | Secure file access | [@modelcontextprotocol/server-filesystem](https://github.com/modelcontextprotocol/servers) |
| **sqlite** | Database queries | [@modelcontextprotocol/server-sqlite](https://github.com/modelcontextprotocol/servers) |
| **postgres** | PostgreSQL access | [@modelcontextprotocol/server-postgres](https://github.com/modelcontextprotocol/servers) |
| **brave-search** | Web search | [@anthropic-ai/mcp-server-brave-search](https://github.com/anthropics/mcp-servers) |
| **fetch** | HTTP requests | [@anthropic-ai/mcp-server-fetch](https://github.com/anthropics/mcp-servers) |
| **github** | Repository access | [@modelcontextprotocol/server-github](https://github.com/modelcontextprotocol/servers) |

### MCP Documentation

- [MCP Specification](https://modelcontextprotocol.io)
- [MCP Server Registry](https://github.com/modelcontextprotocol/servers)
- [Building MCP Servers](https://modelcontextprotocol.io/docs/servers)
- [Claude Code MCP Guide](../docs/guides/claude-code-cli-guide.md#mcp-servers-integration)

---

## Additional Development Guides

### This Repository

| Guide | Focus | Link |
|-------|-------|------|
| **Claude Code CLI** | Anthropic's agentic CLI | [claude-code-cli-guide.md](../docs/guides/claude-code-cli-guide.md) |
| **Gemini CLI** | Google's 1M context AI agent | [gemini-cli-guide.md](../docs/guides/gemini-cli-guide.md) |
| **Google ADK** | Agent Development Kit | [google-adk-guide.md](../docs/guides/google-adk-guide.md) |
| **Cursor IDE** | AI-native IDE | [cursor-ide-guide.md](../docs/guides/cursor-ide-guide.md) |
| **AI Tools Comparison** | Tool selection guide | [ai-dev-tools-comparison.md](../docs/guides/ai-dev-tools-comparison.md) |
| **Workshops Guide** | Hands-on exercises | [workshops-guide.md](../docs/guides/workshops-guide.md) |

---

## YouTube Channels & Video Resources

### AI/ML Development

| Channel | Focus | Link |
|---------|-------|------|
| **Andrej Karpathy** | Neural networks, LLMs | [youtube.com/@AndrejKarpathy](https://www.youtube.com/@AndrejKarpathy) |
| **3Blue1Brown** | Math & ML visualization | [youtube.com/@3blue1brown](https://www.youtube.com/@3blue1brown) |
| **Sentdex** | Python ML tutorials | [youtube.com/@sentdex](https://www.youtube.com/@sentdex) |
| **Two Minute Papers** | AI research summaries | [youtube.com/@TwoMinutePapers](https://www.youtube.com/@TwoMinutePapers) |
| **Yannic Kilcher** | Paper explanations | [youtube.com/@YannicKilcher](https://www.youtube.com/@YannicKilcher) |

### Security & DFIR

| Channel | Focus | Link |
|---------|-------|------|
| **13Cubed** | DFIR tutorials | [youtube.com/@13Cubed](https://www.youtube.com/@13Cubed) |
| **John Hammond** | CTF, malware analysis | [youtube.com/@_JohnHammond](https://www.youtube.com/@_JohnHammond) |
| **IppSec** | HackTheBox walkthroughs | [youtube.com/@ippsec](https://www.youtube.com/@ippsec) |
| **LiveOverflow** | Security research | [youtube.com/@LiveOverflow](https://www.youtube.com/@LiveOverflow) |
| **NetworkChuck** | Networking, security | [youtube.com/@NetworkChuck](https://www.youtube.com/@NetworkChuck) |

---

## Newsletters & Blogs

### AI/ML Security

| Resource | Focus | Link |
|----------|-------|------|
| **The Batch** | Weekly AI news | [deeplearning.ai/the-batch](https://www.deeplearning.ai/the-batch/) |
| **Import AI** | AI research digest | [importai.substack.com](https://importai.substack.com) |
| **AI Snake Oil** | AI critical analysis | [aisnakeoil.com](https://www.aisnakeoil.com) |
| **Simon Willison** | LLM tools & techniques | [simonwillison.net](https://simonwillison.net) |
| **Anthropic Research** | Claude developments | [anthropic.com/research](https://www.anthropic.com/research) |

### Security

| Resource | Focus | Link |
|----------|-------|------|
| **Krebs on Security** | Security news | [krebsonsecurity.com](https://krebsonsecurity.com) |
| **The Hacker News** | Security news | [thehackernews.com](https://thehackernews.com) |
| **Risky Business** | Security podcast | [risky.biz](https://risky.biz) |
| **SANS Reading Room** | Research papers | [sans.org/reading-room](https://www.sans.org/white-papers/) |
| **SpecterOps Blog** | Red/blue team | [specterops.io/blog](https://specterops.io/blog) |

---

**Next**: Return to [Training Program](../docs/ai-security-training-program.md) to start learning.

**Development Guides**: [Claude Code CLI](../docs/guides/claude-code-cli-guide.md) | [Google ADK](../docs/guides/google-adk-guide.md) | [Cursor IDE](../docs/guides/cursor-ide-guide.md) | [AI Tools Comparison](../docs/guides/ai-dev-tools-comparison.md)

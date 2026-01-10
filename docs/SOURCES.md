# Sources and Attribution

This document lists all external sources, tools, frameworks, and documentation used in creating the AI for the Win training program.

## Overview

**All content in this repository is based exclusively on publicly available information.** This project focuses on open-source tooling and publicly documented security concepts to ensure complete transparency and independence.

---

## Open-Source Security Tools

### SIEM and Data Platforms

- **[Elasticsearch](https://www.elastic.co/elasticsearch/)** - Open-source search and analytics engine
  - [EQL (Event Query Language)](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) - Public documentation
  - [ES|QL](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html) - Public documentation
  - License: Elastic License 2.0 and SSPL

- **[OpenSearch](https://opensearch.org/)** - Open-source search and analytics suite (Elasticsearch fork)
  - [OpenSearch Documentation](https://opensearch.org/docs/latest/)
  - License: Apache 2.0

### Detection Engineering

- **[Sigma](https://github.com/SigmaHQ/sigma)** - Generic signature format for SIEM systems
  - [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
  - License: LGPL-2.1

- **[YARA](https://github.com/VirusTotal/yara)** - Pattern matching tool for malware research
  - [YARA Documentation](https://yara.readthedocs.io/)
  - License: BSD-3-Clause

### Threat Intelligence and Frameworks

- **[MITRE ATT&CK](https://attack.mitre.org/)** - Knowledge base of adversary tactics and techniques
  - [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
  - License: Public domain (Terms of Use apply)

- **[MITRE D3FEND](https://d3fend.mitre.org/)** - Knowledge graph of cybersecurity countermeasures
  - License: Public domain

- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Framework for managing cybersecurity risk
  - License: Public domain (U.S. government work)

### Malware Analysis

- **[pefile](https://github.com/erocarrera/pefile)** - Python module for working with Portable Executable files
  - License: MIT

- **[Volatility](https://github.com/volatilityfoundation/volatility3)** - Memory forensics framework
  - License: Volatility Software License

---

## Machine Learning and AI Frameworks

### Core ML Libraries

- **[scikit-learn](https://scikit-learn.org/)** - Machine learning library for Python
  - License: BSD-3-Clause

- **[PyTorch](https://pytorch.org/)** - Open-source machine learning framework
  - License: BSD-3-Clause

- **[Hugging Face Transformers](https://huggingface.co/docs/transformers/)** - State-of-the-art NLP models
  - License: Apache 2.0

### LLM and Agent Frameworks

- **[LangChain](https://python.langchain.com/)** - Framework for building LLM applications
  - [LangChain Documentation](https://python.langchain.com/docs/get_started/introduction)
  - License: MIT

- **[LangGraph](https://langchain-ai.github.io/langgraph/)** - Library for building stateful multi-actor applications
  - License: MIT

- **[LiteLLM](https://github.com/BerriAI/litellm)** - Unified interface for 100+ LLM providers
  - License: MIT

- **[Instructor](https://github.com/jxnl/instructor)** - Structured outputs from LLMs
  - License: MIT

### Vector Databases

- **[ChromaDB](https://www.trychroma.com/)** - Open-source embedding database
  - [ChromaDB Documentation](https://docs.trychroma.com/)
  - License: Apache 2.0

- **[sentence-transformers](https://www.sbert.net/)** - Framework for state-of-the-art sentence embeddings
  - License: Apache 2.0

---

## LLM Provider APIs

All LLM integrations use publicly documented APIs:

- **[Anthropic Claude API](https://docs.anthropic.com/)** - Public API documentation
  - [Claude Model Documentation](https://docs.anthropic.com/en/docs/models-overview)

- **[OpenAI API](https://platform.openai.com/docs/)** - Public API documentation
  - [GPT-4 Documentation](https://platform.openai.com/docs/models/gpt-4)

- **[Google Gemini API](https://ai.google.dev/docs)** - Public API documentation
  - [Gemini Models](https://ai.google.dev/models/gemini)

- **[Ollama](https://ollama.ai/)** - Local LLM runtime (no API key required)
  - License: MIT

---

## Web Frameworks and UI Tools

- **[Gradio](https://www.gradio.app/)** - Framework for building ML web interfaces
  - License: Apache 2.0

- **[Streamlit](https://streamlit.io/)** - Framework for data apps
  - License: Apache 2.0

- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern web framework for APIs
  - License: MIT

---

## Data Sources and Datasets

All datasets used in this project are either:

1. **Synthetic/Generated** - Created specifically for training purposes
2. **Public domain** - Freely available without restrictions
3. **Open-source licensed** - Used in accordance with license terms

Specific data sources are documented within individual lab directories.

---

## Educational Resources

This project draws on concepts from publicly available educational materials:

- Academic research papers (cited where used)
- Public conference presentations (DEF CON, Black Hat, RSA)
- Open-source project documentation
- Publicly available vendor blog posts and white papers
- Community-contributed tutorials and guides

**All references are to publicly available materials only.**

---

## Commercial Security Platforms

### Current Status: Open-Source Only

This project **currently focuses exclusively on open-source security tooling** (Elasticsearch, OpenSearch, Sigma, YARA) to ensure complete independence from proprietary vendor implementations.

### Future Considerations

Commercial security platform references may be added in the future **only if**:

1. ✅ Based entirely on **publicly available vendor documentation**
2. ✅ Cleared by appropriate **legal review**
3. ✅ Clearly **documented with public sources**
4. ✅ Used for **educational comparison purposes only**
5. ✅ Does **not** include proprietary implementations, architectures, or trade secrets

Any future additions will be documented in this file with:
- Public documentation URLs
- Specific features/capabilities referenced
- Date of last verification
- Legal clearance confirmation

---

## Verification and Transparency

### How to Verify Public Availability

All sources listed above can be independently verified:

1. **Official documentation links** - Direct URLs to public vendor docs
2. **Open-source repositories** - Publicly accessible GitHub/GitLab projects
3. **License information** - Clearly stated and verifiable
4. **Archive availability** - Most sources archived via Internet Archive

### Updates and Maintenance

This document is updated whenever:
- New tools or frameworks are introduced
- External dependencies change
- Documentation sources are updated
- Commercial platform references are considered

---

## Contact

If you have questions about the sources used in this project or believe any content may not be properly attributed, please [open an issue](https://github.com/depalmar/ai_for_the_win/issues) or contact the author.

---

*Last updated: January 2026*

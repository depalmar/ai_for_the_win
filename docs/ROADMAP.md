# AI for the Win - Roadmap

> Last updated: January 2026 | Current version: 1.8.0

## Vision

Build the most comprehensive, hands-on AI/ML training program for security practitioners - vendor-agnostic, practical, and community-driven.

---

## Current Status (v1.8.0)

### Completed
- 30+ hands-on labs covering ML, LLM, DFIR, Cloud, and adversarial techniques
- XQL reference guide, templates, and validation tool
- 15 CTF challenges (Beginner, Intermediate, Advanced)
- Multi-provider LLM support (Anthropic, OpenAI, Gemini, Ollama)
- Comprehensive documentation
- Docker Compose lab environment with Jupyter, Elasticsearch, Ollama
- Cloud-Native Security Track (Labs 19b-d)
- AI/ML Security Track (Labs 17b-c, 18b)

### In Progress
- Additional DFIR deep-dives
- XQL query library expansion
- Test coverage improvements

---

## Short-Term (Q1 2026)

### CTF Challenge Expansion
- [x] **Intermediate Challenges** (5 challenges) ✓ v1.3.0
  - C2 Hunter - Beaconing detection, DNS tunneling
  - Memory Forensics - Process injection, credential dumping
  - Adversarial Samples - ML evasion techniques
  - Agent Investigation - ReAct debugging
  - Ransomware Response - Full IR scenario

- [x] **Advanced Challenges** (5 challenges) ✓ v1.3.0
  - APT Attribution - Multi-stage attack correlation
  - Model Poisoning - Training data attacks
  - Cloud Compromise - AWS/Azure/GCP scenarios
  - Zero-Day Hunt - Behavioral anomaly detection
  - Full IR Scenario - End-to-end incident response

### XQL Tools
- [x] Build query validation tool (Python-based syntax checker) ✓ v1.8.0
- [x] Create XQL cheat sheet (quick reference card) ✓ v1.7.0

### Testing & Quality
- [ ] Achieve 80%+ test coverage across all labs
- [ ] Add integration tests for LLM-dependent labs
- [ ] Create automated solution validators

---

## Medium-Term (Q2-Q3 2026)

### New Lab Tracks

#### Cloud-Native Security Track ✓ Completed v1.8.0
- [x] **Lab 19b: Container Security** - Kubernetes threat detection, pod security, runtime analysis
- [x] **Lab 19c: Serverless Security** - Lambda/Functions analysis, event injection detection
- [x] **Lab 19d: Cloud IR Automation** - Automated containment, evidence preservation

#### AI/ML Security Track ✓ Completed v1.8.0
- [x] **Lab 17b: LLM Security Testing** - Automated red team for AI applications
- [x] **Lab 17c: Model Monitoring** - Drift detection, adversarial input detection
- [x] **Lab 18b: RAG Security** - Data poisoning, prompt leakage, extraction attacks

### Infrastructure
- [x] **Docker Compose Lab Environment** ✓ v1.8.0
  - Full lab stack in containers (Jupyter, Elasticsearch, Kibana, Redis, PostgreSQL)
  - Pre-configured Jupyter environments with security tools
  - Ollama for local LLM inference (GPU and CPU-only options)
  - ChromaDB for vector storage (RAG labs)
  - One-command setup: `docker compose up -d`

- [ ] **Progress Tracking**
  - Lab completion badges
  - Skill assessments
  - Learning path recommendations

### Documentation
- [ ] Video walkthroughs for complex labs
- [ ] Instructor guide for classroom use
- [ ] Certification prep alignment (GIAC, OSCP, etc.)

---

## Long-Term (Q4 2026+)

### Platform Evolution
- [ ] **Web-based Lab Platform**
  - Browser-based code execution
  - Integrated scoring system
  - Team competitions

### Content Expansion
- [ ] **Threat Actor Simulations**
  - APT emulation scenarios
  - Real-world breach reconstructions
  - Purple team exercises

- [ ] **Specialized Tracks**
  - OT/ICS Security
  - Mobile threat analysis
  - macOS/Linux forensics

### Community
- [ ] Contribution guidelines for community labs
- [ ] Lab authoring toolkit
- [ ] Community challenge submissions

---

## Technical Debt & Maintenance

### Immediate
- [x] Fix Black formatting in test files
- [ ] Fix CodeQL workflow permissions (TokenPermissionsID)
- [ ] Pin GitHub Actions dependencies (PinnedDependenciesID)

### Ongoing
- [ ] Keep dependencies updated (monthly review)
- [ ] Update LLM model references as new versions release
- [ ] Refresh threat actor data quarterly

---

## Contribution Opportunities

### Good First Issues
- Add test cases for existing labs
- Improve lab README documentation
- Create additional XQL query examples
- Translate documentation

### Help Wanted
- Video tutorial creation
- Localization (non-English)
- Accessibility improvements
- Docker environment testing

---

## Metrics & Goals

| Metric | Current | Q2 2026 Target |
|--------|---------|----------------|
| Labs | 30+ | 35+ |
| CTF Challenges | 15 | 20 |
| Test Coverage | ~70% | 80% |
| XQL Templates | 25+ | 40 |

---

## Feedback & Requests

Have ideas for new labs or improvements?

1. Open an issue with the `enhancement` label
2. Join discussions in GitHub Discussions
3. Submit PRs for community contributions

---

*This roadmap is a living document and will be updated as priorities evolve.*

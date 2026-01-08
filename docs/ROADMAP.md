# AI for the Win - Roadmap

> Last updated: January 2026 | Current version: 1.7.0

## Vision

Build the most comprehensive, hands-on AI/ML training program for security practitioners - vendor-agnostic, practical, and community-driven.

---

## Current Status (v1.7.0)

### Completed
- 25+ hands-on labs covering ML, LLM, DFIR, and adversarial techniques
- XQL reference guide and templates
- CTF beginner challenges
- Multi-provider LLM support (Anthropic, OpenAI, Gemini, Ollama)
- Comprehensive documentation

### In Progress
- Intermediate/Advanced CTF challenges
- Additional DFIR deep-dives
- XQL query library expansion

---

## Short-Term (Q1 2026)

### CTF Challenge Expansion
- [ ] **Intermediate Challenges** (5 challenges)
  - C2 Hunter - Beaconing detection, DNS tunneling
  - Memory Forensics - Process injection, credential dumping
  - Adversarial Samples - ML evasion techniques
  - Agent Investigation - ReAct debugging
  - Ransomware Response - Full IR scenario

- [ ] **Advanced Challenges** (5 challenges)
  - APT Attribution - Multi-stage attack correlation
  - Model Poisoning - Training data attacks
  - Cloud Compromise - AWS/Azure/GCP scenarios
  - Zero-Day Hunt - Behavioral anomaly detection
  - Full IR Scenario - End-to-end incident response

### XQL Tools
- [ ] Build query validation tool (Python-based syntax checker)
- [ ] Create XQL cheat sheet (quick reference card)

### Testing & Quality
- [ ] Achieve 80%+ test coverage across all labs
- [ ] Add integration tests for LLM-dependent labs
- [ ] Create automated solution validators

---

## Medium-Term (Q2-Q3 2026)

### New Lab Tracks

#### Cloud-Native Security Track
- [ ] **Lab 19b: Container Security** - Kubernetes threat detection, pod security, runtime analysis
- [ ] **Lab 19c: Serverless Security** - Lambda/Functions analysis, cold start attacks
- [ ] **Lab 19d: Cloud IR Automation** - Automated containment, evidence preservation

#### AI/ML Security Track
- [ ] **Lab 17b: LLM Security Testing** - Automated red team for AI applications
- [ ] **Lab 17c: Model Monitoring** - Drift detection, adversarial input detection
- [ ] **Lab 18b: RAG Security** - Data poisoning, prompt leakage, extraction attacks

### Infrastructure
- [ ] **Docker Compose Lab Environment**
  - Full lab stack in containers
  - Pre-configured Jupyter environments
  - Sample data generation scripts
  - One-command setup: `docker-compose up`

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
| Labs | 25+ | 30+ |
| CTF Challenges | 2 | 12 |
| Test Coverage | ~60% | 80% |
| XQL Templates | 15 | 30 |

---

## Feedback & Requests

Have ideas for new labs or improvements?

1. Open an issue with the `enhancement` label
2. Join discussions in GitHub Discussions
3. Submit PRs for community contributions

---

*This roadmap is a living document and will be updated as priorities evolve.*

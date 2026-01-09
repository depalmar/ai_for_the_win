# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-01-07

### Added
- **Cloud-Native Security Track**
  - Lab 46: Container Security - Image analysis, runtime detection, Kubernetes audit logs, container escape detection
  - Lab 47: Serverless Security - Function log analysis, event injection detection, IAM permission analysis
  - Lab 48: Cloud IR Automation - Automated containment, evidence collection, Step Functions orchestration

- **AI Security Track**
  - Lab 40: LLM Security Testing - Prompt injection testing, jailbreak evaluation, data extraction tests
  - Lab 41: Model Monitoring - Data drift detection, adversarial input detection, model extraction monitoring
  - Lab 43: RAG Security - Knowledge base poisoning detection, context sanitization, access control

- **Docker Lab Environment** (`docker/`)
  - One-command setup with `docker compose up -d`
  - Jupyter Lab with security-focused Python environment
  - Elasticsearch + Kibana for log analysis
  - PostgreSQL, Redis, MinIO for data storage
  - Ollama for local LLM inference
  - ChromaDB for vector storage (RAG labs)

### Changed
- Updated labs README with new tracks and labs

## [1.7.0] - 2026-01-07

### Added
- **New DFIR Labs**
  - Lab 26: Windows Event Log Analysis - Event IDs, lateral movement patterns, credential theft detection
  - Lab 27: Windows Registry Forensics - Persistence hunting, UserAssist, ShimCache, MRU artifacts
  - Lab 28: Live Response - Collection techniques, order of volatility, triage checklist

- **Test Coverage**
  - Added test files for labs 04, 02, 03, 04, 05, 06a, 07, 07b, 10a

### Changed
- Updated labs README with new DFIR labs
- Fixed CTF challenge directory paths
- Improved CTF beginner challenge descriptions

## [1.6.0] - 2026-01-07

### Added
- **New Lab**
  - Lab 23: CTF Fundamentals - Bridge lab teaching CTF mindset, flag formats, encoding techniques, and systematic approaches to security challenges

- **New CTF Challenges**
  - Intermediate-06: Insider Threat - Detect data exfiltration via DNS tunneling and cloud storage
  - Advanced-05: Zero-Day Hunt - Identify novel exploitation techniques without signatures
  - Advanced-06: Supply Chain - Detect typosquatted packages and dependency confusion attacks

- **Enhanced Vibe Coding Guidance**
  - Part 7: Vibe Coding the Other Labs - Example prompts for Labs 01-04
  - Part 8: Prompt Library & Resources - Links to security prompts library
  - CTF-specific vibe coding examples in Lab 23

### Changed
- Improved OpenSSF Scorecard compliance with job-level permissions
- Added CodeQL exclusions for educational lab content
- Dependency review now warns instead of fails for CTF challenges (intentional vulnerabilities)

### Fixed
- Password strength analyzer thresholds aligned with achievable scores

## [1.3.1] - 2026-01-05

### Changed
- **License Update**: Switched to dual licensing model
  - Educational content (docs, labs, prose): CC BY-NC-SA 4.0
  - Code samples and scripts: MIT License
- Added ShareAlike requirement for derivative content
- Added clear definitions for personal vs. commercial use
- Added commercial licensing pathway for organizations

## [1.3.0] - 2026-01-03

### Added
- **New Labs**
  - Lab 37: AI-Powered Threat Actors - Detect AI-generated phishing, vishing, and malware
  - Lab 50: AI-Assisted Purple Team - Attack simulation and detection gap analysis

- **Threat Actor Database** (`data/threat-actor-ttps/`)
  - 8 new threat actor profiles: Scattered Spider, Volt Typhoon, ALPHV/BlackCat, LockBit, Cl0p, Rhysida, Akira, Play
  - Campaign data: SolarWinds, Colonial Pipeline, MOVEit, MGM/Caesars, Log4Shell, Kaseya
  - Attack chain templates: Double extortion, supply chain, BEC fraud, insider threat

- **CTF Gamification System**
  - 15 achievements (First Blood, Speed Demon, Completionist, etc.)
  - 8 ranks from Script Kiddie to CISO Material
  - 7 specialization badges
  - Prerequisite lab mapping for all challenges

- **CTF Challenge Improvements**
  - Proper embedded flags in beginner-01, beginner-02, intermediate-05, advanced-01
  - Expanded auth_logs.json with realistic 30+ attempt brute force attack
  - APT attribution challenge with MITRE ATT&CK mapping

### Changed
- Updated threat actor profiles with 2024-2025 campaigns and TTPs
- Enhanced CTF README with detailed challenge tables and lab prerequisites
- Improved data documentation with usage examples

### Fixed
- Black formatting issues in lab37 and lab50
- Stale PR cleanup

## [1.2.0] - 2026-01-03

### Changed
- Updated LLM pricing to January 2026 rates
- License changed from MIT to CC BY-NC 4.0

## [1.1.0] - 2026-01-02

### Added
- Lab walkthroughs for all labs
- SANS resource references
- Cloud security fundamentals (Lab 44)
- Sigma rule fundamentals (Lab 49)
- Ransomware fundamentals (Lab 30)

### Changed
- LLM provider agnostic configuration
- Model references updated to latest versions

## [1.0.0] - 2025-12-15

### Added
- Initial release with 25+ hands-on labs
- 15 CTF challenges across beginner, intermediate, and advanced levels
- Comprehensive documentation and walkthroughs
- Docker support
- Google Colab integration

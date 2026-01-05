# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - Lab 16b: AI-Powered Threat Actors - Detect AI-generated phishing, vishing, and malware
  - Lab 20b: AI-Assisted Purple Team - Attack simulation and detection gap analysis

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
- Black formatting issues in lab16b and lab20b
- Stale PR cleanup

## [1.2.0] - 2026-01-03

### Changed
- Updated LLM pricing to January 2026 rates
- License changed from MIT to CC BY-NC 4.0

## [1.1.0] - 2026-01-02

### Added
- Lab walkthroughs for all labs
- SANS resource references
- Cloud security fundamentals (Lab 19a)
- Sigma rule fundamentals (Lab 07b)
- Ransomware fundamentals (Lab 11a)

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

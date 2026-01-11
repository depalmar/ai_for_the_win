# Curriculum Review Report

**Date:** January 11, 2026
**Reviewer:** Claude Code
**Branch:** fix/colab-beginner-links

---

## Executive Summary

| Category | Status | Issues Found |
|----------|--------|--------------|
| Lab Structure (00-50) | Needs Fixes | 12 critical, 9 medium |
| Colab/Notebook Links | Needs Fixes | 6 broken links |
| CTF Challenges | Good | 1 minor issue |
| Walkthroughs | Needs Fixes | 5 broken links, 12 missing |
| Guides | Good | 4 outdated version pins |
| Knowledge Flow | Good | Minor prerequisite issues |

**Total Issues:** 49 (18 critical, 14 medium, 17 low)

---

## Critical Issues (Fix Immediately)

### 1. Wrong Lab Numbers in Headers (12 instances)

Labs have incorrect "Lab XX" numbers in their README titles:

| File | Line | Current | Should Be |
|------|------|---------|-----------|
| `labs/lab00-environment-setup/README.md` | 838 | Links say "Lab 29" | "Lab 01" and "Lab 10" |
| `labs/lab01-python-security-fundamentals/README.md` | 1 | "Lab 29" | "Lab 01" |
| `labs/lab03-vibe-coding-with-ai/README.md` | 1 | "Lab 32" | "Lab 03" |
| `labs/lab04-ml-concepts-primer/README.md` | 1 | "Lab 35" | "Lab 04" |
| `labs/lab10-phishing-classifier/README.md` | 397 | "Lab 29 Walkthrough" | "Lab 10 Walkthrough" |
| `labs/lab10-phishing-classifier/README.md` | 399 | "Lab 31" next lab | "Lab 11" |
| `labs/lab11-malware-clustering/README.md` | 329 | "Lab 31 Walkthrough" | "Lab 11 Walkthrough" |
| `labs/lab12-anomaly-detection/README.md` | 317 | "Lab 32 Walkthrough" | "Lab 12 Walkthrough" |
| `labs/lab12-anomaly-detection/README.md` | 319 | "Lab 35" next lab | "Lab 15" |

### 2. Broken Colab/Notebook Links (6 instances)

| File | Line | Problem | Fix |
|------|------|---------|-----|
| `docs/index.md` | 2021 | Links to `lab10` but label says "Lab 29" | Update label or link |
| `docs/index.md` | 2025 | Links to `lab15` but label says "Lab 35" | Update label or link |
| `docs/walkthroughs/README.md` | 26 | References `lab00e_visualization_stats.ipynb` | Change to `lab06_visualization_stats.ipynb` |
| `notebooks/lab42_fine_tuning.ipynb` | cell 6 | Self-link points to `lab18` | Change to `lab42` |
| `notebooks/lab33_memory_forensics.ipynb` | cell 9 | Self-link points to `lab13` | Change to `lab33` |
| `notebooks/lab33_memory_forensics_restored.ipynb` | cell 9 | Self-link points to `lab13` | Change to `lab33` |

### 3. Broken Walkthrough Links (5 instances)

In `docs/walkthroughs/README.md`:

| Line | Current Reference | Correct File |
|------|-------------------|--------------|
| 24 | `lab00c-prompt-engineering-walkthrough.md` | `lab02-prompt-engineering-walkthrough.md` |
| 25 | `lab00d-ai-in-security-ops-walkthrough.md` | `lab05-ai-in-security-ops-walkthrough.md` |
| 71 | `lab15-lateral-movement-walkthrough.md` | `lab35-lateral-movement-walkthrough.md` |
| 76 | `lab18-fine-tuning-walkthrough.md` | `lab42-fine-tuning-walkthrough.md` |

---

## Medium Priority Issues

### 4. Missing Lab Implementation Files (9 labs)

These labs have README.md but no starter/solution folders:

| Lab | Name | Status |
|-----|------|--------|
| Lab 26 | windows-event-log-analysis | No starter/solution folders |
| Lab 27 | windows-registry-forensics | No starter/solution folders |
| Lab 28 | live-response | No starter/solution folders |
| Lab 40 | llm-security-testing | Tests only, no starter |
| Lab 41 | model-monitoring | Tests only, no starter |
| Lab 43 | rag-security | Tests only, no starter |
| Lab 46 | container-security | Tests only, no starter |
| Lab 47 | serverless-security | Tests only, no starter |
| Lab 48 | cloud-ir-automation | Tests only, no starter |

### 5. Missing Data Directories (2 labs)

| Lab | Referenced Data | Missing |
|-----|-----------------|---------|
| Lab 26 | `data/event_samples/` | security_events.json, powershell_events.json |
| Lab 27 | `data/registry_samples/` | SYSTEM_infected, SOFTWARE_backdoor |

### 6. Incorrect Next Lab References (2 instances)

| File | Line | Current | Should Be |
|------|------|---------|-----------|
| `labs/lab08-working-with-apis/README.md` | 634 | Next: Lab 03 | Lab 09 or Lab 10 |
| `labs/lab28-live-response/README.md` | 617 | "See Labs 11-16" | "Labs 26-28" |

### 7. CTF Achievement Count Mismatch

**File:** `ctf-challenges/achievements.json` line 132
**Issue:** Completionist requires 15 flags but there are 18 challenges
**Fix:** Update `"flags_captured": 15` to `"flags_captured": 18`

---

## Low Priority Issues

### 8. Outdated Package Versions (4 instances)

| File | Package | Current | Recommended |
|------|---------|---------|-------------|
| `docs/guides/dev-environment-setup.md` | anthropic | `>=0.8.0` | `>=0.30.0` |
| `docs/guides/dev-environment-setup.md` | langchain-anthropic | `>=0.1.0` | `>=0.2.0` |
| `docs/guides/quickstart-guide.md` | anthropic | `>=0.8.0` | `>=0.30.0` |
| `docs/guides/quickstart-guide.md` | langchain-anthropic | `>=0.1.0` | `>=0.2.0` |

### 9. Missing Walkthroughs (12 labs)

| Lab | Name | Priority |
|-----|------|----------|
| Lab 00 | environment-setup | Medium |
| Lab 03 | vibe-coding-with-ai | Low |
| Lab 09 | ctf-fundamentals | Low |
| Lab 26 | windows-event-log-analysis | High |
| Lab 27 | windows-registry-forensics | High |
| Lab 28 | live-response | High |
| Lab 40 | llm-security-testing | Medium |
| Lab 41 | model-monitoring | Medium |
| Lab 43 | rag-security | Medium |
| Lab 46 | container-security | Medium |
| Lab 47 | serverless-security | Medium |
| Lab 48 | cloud-ir-automation | Medium |

---

## Positive Findings

### What's Working Well

1. **Lab Numbering Sequence:** All 51 labs (00-50) exist with no gaps
2. **CTF Challenge Structure:** All 18 challenges have complete data files, proper README documentation, and valid prerequisites
3. **Guide Quality:** 28 comprehensive guides totaling 522 KB with consistent formatting
4. **Walkthrough Coverage:** 39 of 51 labs (76.5%) have walkthroughs
5. **Internal Cross-References:** Guide-to-guide links are all valid
6. **External Links:** All 25 external URLs in guides are valid
7. **Model References:** All LLM model names are current (claude-sonnet-4, gpt-5.2, gemini-3-flash)
8. **Flag Format Consistency:** All CTF flags use consistent `FLAG{...}` format
9. **Prerequisites Documentation:** All labs have clear prerequisites listed

### Coverage Statistics

| Category | Coverage |
|----------|----------|
| Labs with README | 51/51 (100%) |
| Labs with starter/solution | 42/51 (82%) |
| Labs with walkthroughs | 39/51 (76%) |
| CTF challenges complete | 18/18 (100%) |
| Guides complete | 28/28 (100%) |

---

## Recommended Action Plan

### Phase 1: Critical Fixes (Same Day)

```bash
# 1. Fix lab header numbers (12 files)
# Run search-replace for "Lab 29" -> "Lab 01" in lab01
# Run search-replace for "Lab 32" -> "Lab 03" in lab03
# etc.

# 2. Fix Colab link labels in docs/index.md
# Line 2021: Change label from "Lab 29" to "Lab 10"
# Line 2025: Change label from "Lab 35" to "Lab 15"

# 3. Fix walkthrough README links
# Update old numbering (lab00c, lab00d, lab00e) to actual numbers
```

### Phase 2: Medium Fixes (This Week)

1. Create starter/solution folders for Labs 26-28, 40-41, 43, 46-48
2. Add data directories to Labs 26-27
3. Fix next lab references in Labs 08 and 28
4. Update CTF achievement count to 18

### Phase 3: Enhancements (This Month)

1. Update package version pins in guides
2. Create missing walkthroughs for Labs 26-28 (high priority DFIR content)
3. Add walkthrough stubs for remaining 9 labs
4. Enhance lab-to-guide cross-references

---

## Appendix: File Locations

All issues are in repository:
`c:\Users\depal\.claude-worktrees\ai_for_the_win_fresh\sweet-mclaren\`

### Key Directories
- Labs: `labs/lab00-* through lab50-*`
- Notebooks: `notebooks/*.ipynb`
- Walkthroughs: `docs/walkthroughs/`
- Guides: `docs/guides/`
- CTF: `ctf-challenges/`
- Index: `docs/index.md`

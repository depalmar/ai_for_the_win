# AI for the Win - Claude Instructions

## Project Overview

Security training curriculum with 50+ labs covering ML, LLM, DFIR, and cloud security.

## MANDATORY: Web Search Before Editing Security Content

**STOP. Before editing ANY of these files, you MUST perform web searches first:**

### Protected Files (Require Web Search)

```
labs/lab30-ransomware-fundamentals/     - Search: ransomware groups 2025
labs/lab31-ransomware-detection/        - Search: ransomware detection 2025
labs/lab32-ransomware-simulation/       - Search: ransomware TTPs 2025
labs/lab37-ai-powered-threat-actors/    - Search: APT AI 2025 nation state
labs/lab39-adversarial-ml/              - Search: adversarial ML attacks 2025
labs/lab40-llm-security-testing/        - Search: LLM security OWASP 2025
labs/lab43-rag-security/                - Search: RAG poisoning attacks 2025
labs/lab49-llm-red-teaming/             - Search: LLM red team 2025
docs/guides/threat-landscape-*.md       - Search: ALL threat intel topics
```

### Required Search Queries

| Topic | Search Query |
|-------|-------------|
| APT Groups | `"APT threat actors 2025 2026 campaigns China Russia Iran DPRK"` |
| Ransomware | `"ransomware groups 2025 2026 RaaS RansomHub Qilin"` |
| C2 Frameworks | `"C2 frameworks 2025 Sliver Havoc Mythic Cobalt Strike"` |
| LLM Security | `"LLM security threats 2025 prompt injection OWASP"` |
| AI Attacks | `"AI-powered cyber attacks 2025 APT28 autonomous"` |

### Why This Matters

- Training data is months/years old
- Threat landscape changes weekly
- Outdated threat intel = wrong training = security gaps
- This curriculum must reflect CURRENT threats

### Validation Checklist

Before saving edits:
- [ ] Web search performed for each topic mentioned
- [ ] All threat actor data is 2025+
- [ ] Sources cited with URLs
- [ ] No pre-2024 data without "historical" label

## Quick Commands

| Command | Purpose |
|---------|---------|
| `/update-threat-intel` | Full threat intel update with searches |
| `/ctf` | CTF challenge navigation |
| `/lab` | Lab navigation |

## Testing

Always run before committing:
```bash
python -m pytest tests/test_curriculum_integrity.py -v
```

## Key Reference Files

| File | Content |
|------|---------|
| `docs/guides/threat-landscape-2025.md` | Central threat intel reference |
| `docs/LAB_DEPENDENCY_GRAPH.md` | Prerequisites + threat mapping |
| `labs/lab30-*/README.md` | Ransomware families |
| `labs/lab37-*/README.md` | AI threat actors |

## MCP Servers Available

- `security-tools` - VirusTotal, Shodan, AbuseIPDB, URLScan

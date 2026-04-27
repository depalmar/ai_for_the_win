# Security Code Review

Audit Python (and adjacent) code for security vulnerabilities, secrets, and unsafe patterns.

## Usage

```
/security-check                       # Review the current file (or staged diff)
/security-check <file_or_dir>         # Review a specific path
/security-check --diff                # Review only the git diff vs. main
/security-check --severity high       # Filter to high+ severity findings
```

## Instructions

When the user invokes this command:

1. **Determine scope**:
   - No arg → use current open file or `git diff` if changes are staged
   - File / directory → recurse, skip `__pycache__`, `.venv`, `node_modules`, `.git`
   - `--diff` → only lines changed in `git diff main...HEAD`

2. **Run automated tools first** (don't reinvent):
   ```bash
   bandit -r <path> -ll              # Python static analysis
   pip-audit                          # Dependency CVEs
   safety check                       # Alternative dep scanner
   semgrep --config auto <path>       # Pattern-based linting (if installed)
   ```
   Aggregate findings, dedupe by `(file, line, rule_id)`.

3. **Layer in LLM-driven semantic review** for issues tools miss:

   | Category | Look For |
   |---|---|
   | **Secrets** | Hardcoded API keys, tokens, passwords, AWS creds, private keys |
   | **Injection** | SQL via f-strings, shell via `os.system` / `subprocess(shell=True)`, command via `eval`/`exec` |
   | **Deserialization** | `pickle.loads`, `yaml.load` (without `SafeLoader`), `marshal.loads` on untrusted input |
   | **Crypto** | MD5/SHA1 for security (OK with `usedforsecurity=False`), weak random (`random` for tokens — should be `secrets`), hardcoded IVs/keys |
   | **Path traversal** | User input concatenated into file paths without `Path.resolve().is_relative_to()` |
   | **SSRF** | URL fetches with user-controlled hostnames, no allowlist |
   | **AuthN/AuthZ** | Missing decorators, JWT `none` algo, predictable session IDs |
   | **LLM-specific** | Prompt injection sinks, system prompt leakage, untrusted tool calls, RAG poisoning vectors |
   | **Logging** | PII / secrets / full request bodies in logs |
   | **Deps** | Outdated, known-vulnerable, or unpinned versions |

4. **Output as a triage table**:
   ```
   | Severity | File:Line | Issue | Fix |
   |----------|-----------|-------|-----|
   | HIGH | api.py:42 | Hardcoded API key | Move to env var, rotate key |
   | MED | utils.py:17 | yaml.load unsafe | Use yaml.safe_load |
   ```

5. **For each HIGH/CRITICAL**: provide a concrete patch (diff format) the user can apply.

6. **Never echo found secrets** in chat output — show `<REDACTED:24chars>` placeholder + file:line. If a real secret is detected in a tracked file, **strongly recommend immediate rotation + history rewrite** (the secret is already compromised).

## Project-Specific Rules

Follow rules in:
- `setup/cursor-rules/security.md` (no hardcoded secrets, input validation, IOC handling)
- `CLAUDE.md` (no real victim names, no real IOCs in demo material)
- `LICENSE` (open-source backends only — flag proprietary SDK usage)

## Related

- Skill: `Security > WebAssessment` (for full web app review)
- Skill: `Security > PromptInjection` (for LLM-app pen testing)
- Labs: lab40 (LLM Security Testing), lab43 (RAG Security), lab49 (LLM Red Teaming)

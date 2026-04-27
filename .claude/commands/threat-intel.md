# Threat Intelligence Enrichment

Enrich IOCs with reputation and context from open threat intelligence sources.

## Usage

```
/threat-intel <ioc>                  # Single IOC lookup
/threat-intel --file iocs.json       # Bulk enrichment from file
/threat-intel <ioc> --sources vt,abuseipdb,otx
```

## Instructions

When the user invokes this command:

1. **Detect IOC type** (IP, domain, URL, hash) using patterns from `.claude/knowledge/ioc-patterns.md`.

2. **Check for required API keys** in environment:
   - `VIRUSTOTAL_API_KEY` — VirusTotal (file hashes, URLs, domains, IPs)
   - `ABUSEIPDB_API_KEY` — AbuseIPDB (IP reputation)
   - `OTX_API_KEY` — AlienVault OTX (multi-type, free)
   - `SHODAN_API_KEY` — Shodan (IP infrastructure)

   If a key is missing, skip that source with a `(skipped: no key)` note rather than erroring.

3. **Query each available source** (use the templates in `templates/mcp-servers/threat-intel-mcp-server.py` and `templates/mcp-servers/virustotal-mcp-server.py` for reference logic). Respect rate limits — sleep between requests for free-tier keys.

4. **Aggregate results** into a unified verdict:
   - **threat_score** (0-100) — weighted blend across sources
   - **threat_level** — clean / low / medium / high / critical
   - **mitre_techniques** — map any tagged TTPs to MITRE IDs
   - **recommendations** — block, watchlist, monitor, or whitelist

5. **Output** a markdown summary plus an optional JSON dump. Offer to:
   - Cache results to `~/.cache/aftw-threat-intel/`
   - Generate a detection via `/sigma-create` if score ≥ medium
   - Open a Hunt query via `/threat-hunt`

## Defensive Notes

- **Never log full API keys** — redact in any error output
- **Defang IOCs in chat output** by default (avoid auto-fetch by other tooling)
- **OPSEC**: do NOT submit internal/private IPs or your org's hashes to public sources without explicit confirmation

## Related

- Templates: `templates/mcp-servers/threat-intel-mcp-server.py`
- Knowledge: `.claude/knowledge/ioc-patterns.md`, `.claude/knowledge/mitre-attack.md`
- Labs: lab16 (Threat Intel Agent), lab23 (Detection Pipeline)

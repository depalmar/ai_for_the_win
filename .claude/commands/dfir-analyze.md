# DFIR Analysis

Build a structured Digital Forensics & Incident Response analysis notebook for an artifact, log set, or incident timeline.

## Usage

```
/dfir-analyze <artifact_dir>                  # Auto-discover artifacts in a folder
/dfir-analyze --case CASE-2026-001            # Start a new case workspace
/dfir-analyze <file> --type pcap|memory|disk|logs
```

## Instructions

When the user invokes this command:

1. **Identify artifact type(s)** by extension and magic bytes:
   - **PCAP** (.pcap, .pcapng) → suggest `pyshark`, Zeek, Suricata
   - **Memory** (.raw, .mem, .vmem) → suggest Volatility 3
   - **Disk** (.E01, .dd, .img) → suggest TSK / autopsy workflows
   - **Logs** (.log, .evtx, .json) → route via `/log-parser`
   - **Email** (.eml, .msg) → header analysis + IOC extraction
   - **Malware sample** → static-only triage (NEVER detonate)

2. **Create a structured case workspace**:
   ```
   cases/<CASE-ID>/
   ├── README.md              # Case summary + timeline
   ├── artifacts/             # Original evidence (read-only)
   ├── analysis/              # Notebooks + scripts
   ├── iocs.json              # Extracted via /ioc-extractor
   ├── timeline.csv           # Events with @timestamp
   └── chain-of-custody.md    # Hash + handler log
   ```

3. **Generate a Jupyter notebook** scaffold (`analysis/triage.ipynb`) with cells for:
   - Loading + hashing the artifact (SHA-256 chain of custody)
   - Initial enumeration (file structure, key fields, anomalies)
   - IOC extraction → `/ioc-extractor`
   - Timeline reconstruction → `/timeline-viz`
   - Detection ideas → `/sigma-create`
   - Threat intel enrichment → `/threat-intel`

4. **MITRE ATT&CK mapping**: as findings emerge, map them to tactics/techniques using `.claude/knowledge/mitre-attack.md`. Maintain a running technique table in the case README.

5. **Always include** in the final report:
   - Executive summary (3 sentences)
   - Timeline (UTC, sorted)
   - Indicators (with confidence levels)
   - MITRE coverage matrix
   - Recommended containment / eradication / recovery actions
   - Lessons learned

## OPSEC + Legal

- **Never share real victim data** — labs use mock data only (per `CLAUDE.md` and `global-security` rules)
- **Hash everything** before analysis (MD5 + SHA-256) and record in chain-of-custody.md
- **Read-only mounts** for evidence — do all work on copies
- **Document every action** with timestamps + analyst name

## Related

- Knowledge: `.claude/knowledge/mitre-attack.md`, `.claude/knowledge/log-formats.md`, `.claude/knowledge/ioc-patterns.md`
- Labs: lab25 (DFIR Fundamentals), lab28 (Live Response), lab29 (IR Copilot), lab48 (Cloud IR)
